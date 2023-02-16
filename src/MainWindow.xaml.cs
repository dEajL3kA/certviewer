using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using System.Threading.Tasks;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.IO.Pem;

using CertViewer.Dialogs;
using Microsoft.Win32;

namespace CertViewer
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const int WM_DRAWCLIPBOARD = 0x0308;

        private static readonly Lazy<ILookup<string, string>> EXT_KEY_USAGE = new Lazy<ILookup<string, string>>(CreateLookup_ExtKeyUsage);

        private readonly Regex PEM_CERTIFICATE = new Regex(@"-{3,}\s*BEGIN\s+CERTIFICATE\s*-{3,}(.+)-{3,}\s*END\s+CERTIFICATE\s*-{3,}", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private readonly Regex INVALID_BASE64_CHARS = new Regex(@"[^A-Za-z0-9+/]+", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled);
        
        private IntPtr? m_wndHandle = null;
        private bool m_initialized = false;

        public X509Certificate Certificate { get; private set; }

        // ==================================================================
        // Constructor
        // ==================================================================

        public MainWindow()
        {
            InitializeComponent();
            ShowPlaceholder(true);
            Title += $" [{GetBuildDateTime()}]";
        }

        // ==================================================================
        // Event Handlers
        // ==================================================================

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            HwndSource source = PresentationSource.FromVisual(this) as HwndSource;
            if (!ReferenceEquals(source, null))
            {
                source.AddHook(WndProc);
                SetClipboardViewer((m_wndHandle = source.Handle).Value);
            }
        }

        protected override async void OnContentRendered(EventArgs e)
        {
            base.OnContentRendered(e);
            if (!m_initialized)
            {
                MaxHeight = MinHeight = ActualHeight;
                MinWidth = ActualWidth;
                Checkbox_StayOnTop.IsChecked = Topmost;
                if (!await ParseCliArguments())
                {
                    ParseCertificateFromClipboard();
                }
                m_initialized = true;
            }
        }

        private void Window_PreviewDragEnter(object sender, DragEventArgs e)
        {
            e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
            e.Handled = true;
        }

        private void Window_PreviewDragLeave(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }

        private async void Window_PreviewDrop(object sender, DragEventArgs e)
        {
            string[] droppedFiles = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (!ReferenceEquals(droppedFiles, null))
            {
                foreach (string currentFile in droppedFiles)
                {
                    try
                    {
                        if (await ParseCertificateFile(currentFile))
                        {
                            e.Handled = true;
                            return;
                        }
                    }
                    catch { }
                }
            }
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            switch (msg)
            {
                case WM_DRAWCLIPBOARD:
                    if (m_initialized && Checkbox_MonitorClipboard.IsChecked.GetValueOrDefault(false))
                    {
                        ParseCertificateFromClipboard();
                    }
                    handled = true;
                    break;
            }
            return IntPtr.Zero;
        }

        private void Button_SubjectDN_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (!ReferenceEquals(cert = Certificate, null))
            {
                ShowDistinguishedNameDetails(cert.SubjectDN, "Subject DN");
            }
        }

        private void Button_IssuerDN_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (!ReferenceEquals(cert = Certificate, null))
            {
                ShowDistinguishedNameDetails(cert.IssuerDN, "Issuer DN");
            }
        }

        private void Button_SubjAltNames_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (!ReferenceEquals(cert = Certificate, null))
            {
                ShowSubjAltNamesDetails(cert.GetSubjectAlternativeNames());
            }
        }

        private async void Image_Placeholder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Certificate Files|*.pem;*.der;*.cer;*.crt|All Files|*.*";
            if (openFileDialog.ShowDialog().GetValueOrDefault(false))
            {
                await ParseCertificateFile(openFileDialog.FileName);
            }
        }

        private void StayOnTop_Clicked(object sender, RoutedEventArgs e)
        {
            CheckBox checkbox = sender as CheckBox;
            if (!ReferenceEquals(checkbox, null))
            {
                Topmost = checkbox.IsChecked.GetValueOrDefault(false);
            }
        }

        private void Clear_Clicked(object sender, RoutedEventArgs e)
        {
            Certificate = null;
            TextBox_Asn1Data.Text = TextBox_BasicConstraints.Text = TextBox_DigestSha256.Text = 
                TextBox_ExtKeyUsage.Text = TextBox_Issuer.Text = TextBox_KeyUsage.Text = TextBox_NotAfter.Text =
                TextBox_NotBefore.Text = TextBox_PemData.Text = TextBox_PublicKey.Text = TextBox_Serial.Text =
                TextBox_SignAlgo.Text = TextBox_SubjAltNames.Text = TextBox_Subject.Text = string.Empty;
            ShowPlaceholder(true);
            Tab_Asn1Data.IsEnabled = Tab_PemData.IsEnabled = false;
            TabControl.SelectedItem = Tab_CertInfo;
        }

        private void Label_Placeholder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            FrameworkElement element = sender as FrameworkElement;
            if ((!ReferenceEquals(element, null)) && (element.Visibility == Visibility.Visible))
            {
                element.Visibility = Visibility.Hidden;
            }
        }

        // ==================================================================
        // Internal Methods
        // ==================================================================

        private async Task<bool> ParseCliArguments()
        {
            try
            {
                string[] commandLineArgs = Environment.GetCommandLineArgs();
                if (!ReferenceEquals(commandLineArgs, null))
                {
                    foreach (string filename in commandLineArgs.Skip(1))
                    {
                        if (await ParseCertificateFile(filename))
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private async void ParseCertificateFromClipboard()
        {
            using (OverrideCursor busy = new OverrideCursor())
            {
                await HideErrorText();
                try
                {
                    if (Clipboard.ContainsText())
                    {
                        Match match = PEM_CERTIFICATE.Match(Clipboard.GetText());
                        if (match.Success)
                        {
                            ParseCertificateData(match.Groups[1].Value);
                        }
                    }

                }
                catch { }
            }
        }

        private async Task<bool> ParseCertificateFile(string fileName)
        {
            using (OverrideCursor busy = new OverrideCursor())
            {
                await HideErrorText();
                try
                {
                    byte[] data = File.ReadAllBytes(fileName);
                    Match match = PEM_CERTIFICATE.Match(Encoding.UTF8.GetString(data));
                    if (match.Success)
                    {
                        ParseCertificateData(match.Groups[1].Value);
                    }
                    else
                    {
                        ParseCertificateData(data);
                    }
                    return true;
                }
                catch { }
            }
            return false;
        }

        private void ParseCertificateData(string pemText)
        {
            try
            {
                ParseCertificateData(Convert.FromBase64String(AddPadding(INVALID_BASE64_CHARS.Replace(pemText, string.Empty))));
            }
            catch (Exception e)
            {
                TabControl.SelectedItem = Tab_CertInfo;
                ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}");
            }
        }

        private void ParseCertificateData(byte[] data)
        {
            try
            {
                X509Certificate cert = new X509CertificateParser().ReadCertificate(data);
                if (!ReferenceEquals(Certificate = cert, null))
                {
                    TextBox_Subject.Text = X500NameToRFC2253(cert.SubjectDN);
                    TextBox_Issuer.Text = X500NameToRFC2253(cert.IssuerDN);
                    TextBox_Serial.Text = $"0x{cert.SerialNumber.ToString(16).ToUpperInvariant()}";
                    DateTime notBeforeUtc = cert.NotBefore.ToUniversalTime();
                    DateTime notAfterUtc = cert.NotAfter.ToUniversalTime();
                    TextBox_NotBefore.Text = notBeforeUtc.ToString("yyyy-MM-dd HH\\:mm\\:ss", CultureInfo.InvariantCulture);
                    TextBox_NotAfter.Text = notAfterUtc.ToString("yyyy-MM-dd HH\\:mm\\:ss", CultureInfo.InvariantCulture);
                    int basicConstraints = cert.GetBasicConstraints();
                    TextBox_BasicConstraints.Text = (basicConstraints >= 0) ? $"CA certificate (max. path length: {PathLength(basicConstraints)})" : "End entity certificate";
                    TextBox_KeyUsage.Text = ParseKeyUsage(cert.GetKeyUsage());
                    TextBox_ExtKeyUsage.Text = ParseExtendedKeyUsage(cert.GetExtendedKeyUsage());
                    TextBox_SubjAltNames.Text = ParseSubjectAlternativeNames(cert.GetSubjectAlternativeNames());
                    TextBox_PublicKey.Text = ParsePublicKey(cert.GetPublicKey());
                    TextBox_SignAlgo.Text = $"{cert.SigAlgName} [{cert.SigAlgOid}]";
                    TextBox_DigestSha256.Text = Hex.ToHexString(DigestUtilities.CalculateDigest("SHA-256", cert.GetEncoded())).ToUpperInvariant();
                    DateTime now = DateTime.UtcNow;
                    TextBox_NotBefore.Foreground = (notBeforeUtc > now) ? Brushes.Red : Brushes.DarkGreen;
                    TextBox_NotAfter.Foreground = (notAfterUtc < now) ? Brushes.Red : Brushes.DarkGreen;
                    TextBox_Asn1Data.Text = CreateAsn1Dump(cert.CertificateStructure);
                    TextBox_PemData.Text = CreatePemData(cert.GetEncoded());
                    TabControl.SelectedItem = Tab_CertInfo;
                    Tab_PemData.IsEnabled = true;
                    ShowPlaceholder(false);
                    BringWindowToFront(m_wndHandle);
                }
                else
                {
                    TabControl.SelectedItem = Tab_CertInfo;
                    ShowPlaceholder(true, "Error: Input does not contain a valid X.509 certificate!");
                }
            }
            catch(Exception e)
            {
                TabControl.SelectedItem = Tab_CertInfo;
                ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}");
            }
        }

        private void ShowDistinguishedNameDetails(X509Name name, string title)
        {
            if ((!ReferenceEquals(name, null)) && (!string.IsNullOrWhiteSpace(title)))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IList oidList = name.GetOidList();
                    IList valList = name.GetValueList();
                    if ((!ReferenceEquals(oidList, null)) && (!ReferenceEquals(valList, null)))
                    {
                        IEnumerable<KeyValuePair<string, string>> items = oidList.OfType<DerObjectIdentifier>()
                                .Select(oid => DecodeNameIdentifier(oid))
                                .Zip(valList.OfType<string>(), (key, value) => new KeyValuePair<string, string>(key, value));
                        if (items.Any())
                        {
                            DetailsView viewer = new DetailsView(items.Reverse()) { Owner = this, Title = title };
                            viewer.ShowDialog(busy);
                        }
                    }
                }
            }
        }

        private void ShowSubjAltNamesDetails(ICollection subjectAlternativeNames)
        {
            if (!ReferenceEquals(subjectAlternativeNames, null))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IEnumerable<KeyValuePair<string, string>> items = subjectAlternativeNames.OfType<IList>().Where(item => item.Count >= 2)
                        .Select(item => new KeyValuePair<string, string>(DecodeSubjectAlternativeNameType(item[0] as int?), item[1] as string))
                        .Where(item => !(string.IsNullOrEmpty(item.Key) || string.IsNullOrEmpty(item.Value)));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = "Subject Alternative Names" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }

        private void ShowPlaceholder(bool show, string placeholderText = null)
        {
            Tab_PemData.IsEnabled = Tab_Asn1Data.IsEnabled = show ? false : true;
            Panel_Placeholder.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            Panel_CertInfo.Visibility = show ? Visibility.Hidden : Visibility.Visible;
            Label_Placeholder.Visibility = !string.IsNullOrEmpty(placeholderText) ? Visibility.Visible : Visibility.Hidden;
            Label_Placeholder.Content = !string.IsNullOrEmpty(placeholderText) ? placeholderText : string.Empty;
        }

        private async Task HideErrorText()
        {
            if (Label_Placeholder.Visibility == Visibility.Visible)
            {
                Label_Placeholder.Visibility = Visibility.Hidden;
                await Dispatcher.Yield(DispatcherPriority.Render);
            }
        }

        // ==================================================================
        // Utility Methods
        // ==================================================================

        private static ILookup<string, string> CreateLookup_ExtKeyUsage()
        {
            Dictionary<string, string> builder = new Dictionary<string, string>();
            builder.Add(KeyPurposeID.IdKPServerAuth.Id, "ServerAuth");
            builder.Add(KeyPurposeID.IdKPClientAuth.Id, "ClientAuth");
            builder.Add(KeyPurposeID.IdKPCodeSigning.Id, "CodeSigning");
            builder.Add(KeyPurposeID.IdKPEmailProtection.Id, "EmailProtection");
            builder.Add(KeyPurposeID.IdKPIpsecEndSystem.Id, "IpsecEndSystem");
            builder.Add(KeyPurposeID.IdKPIpsecTunnel.Id, "IpsecTunnel");
            builder.Add(KeyPurposeID.IdKPIpsecUser.Id, "IpsecUser");
            builder.Add(KeyPurposeID.IdKPTimeStamping.Id, "TimeStamping");
            builder.Add(KeyPurposeID.IdKPOcspSigning.Id, "OcspSigning");
            builder.Add(KeyPurposeID.IdKPSmartCardLogon.Id, "SmartCardLogon");
            builder.Add(KeyPurposeID.IdKPMacAddress.Id, "MacAddress");
            return builder.ToLookup(entry => entry.Key, entry => entry.Value);
        }

        private static string ParseKeyUsage(bool[] keyUsageFlags)
        {
            if (!ReferenceEquals(keyUsageFlags, null))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < keyUsageFlags.Length; ++i)
                    {
                        if (keyUsageFlags[i])
                        {
                            Append(sb, DecodeKeyUsage(i));
                        }
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }
            }
            return "(None)";
        }

        private static string DecodeKeyUsage(int index)
        {
            switch (index)
            {
                case 0: return "DigitalSignature";
                case 1: return "NonRepudiation";
                case 2: return "KeyEncipherment";
                case 3: return "DataEncipherment";
                case 4: return "KeyAgreement";
                case 5: return "KeyCertSign";
                case 6: return "CrlSign";
                case 7: return "EncipherOnly";
                case 8: return "DecipherOnly";
            }
            return $"#{index}";
        }

        private static string ParseExtendedKeyUsage(IList extendedKeyUsage)
        {
            if (!ReferenceEquals(extendedKeyUsage, null))
            {
                try
                {
                    ILookup<string, string> lookup = EXT_KEY_USAGE.Value;
                    StringBuilder sb = new StringBuilder();
                    foreach (string usageOid in extendedKeyUsage)
                    {
                        Append(sb, lookup[usageOid].Concat(Once(usageOid)).First());
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }
            }
            return "(None)";
        }

        private static string ParseSubjectAlternativeNames(ICollection subjectAlternativeNames)
        {
            if (!ReferenceEquals(subjectAlternativeNames, null))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    string type;
                    object value;
                    foreach (IList name in subjectAlternativeNames)
                    {
                        if (name.Count >= 2)
                        {
                            if ((!string.IsNullOrEmpty(type = DecodeSubjectAlternativeNameType(name[0] as int?))) && (!ReferenceEquals(value = name[1], null)))
                            {
                                Append(sb, $"{type}: {DecodeSubjectAlternativeNameValue(value)}");
                            }
                        }
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }
            }
            return "(None)";
        }

        private static string DecodeSubjectAlternativeNameType(int? type)
        {
            if (type.HasValue)
            {
                switch (type.Value)
                {
                    case 0: return "OtherName";
                    case 1: return "Email";
                    case 2: return "DNS";
                    case 3: return "X400Address";
                    case 4: return "DirectoryName";
                    case 5: return "EdiPartyName";
                    case 6: return "UniformResourceIdentifier";
                    case 7: return "IPAddress";
                    case 8: return "RegisteredID";
                }
                return $"#{type.Value}";
            }
            return string.Empty;
        }

        private static string DecodeSubjectAlternativeNameValue(object value)
        {
            if (value is string)
            {
                return $"\"{((string)value).Replace("\"", "\\\"")}\"";
            }
            else
            {
                return $"{value.GetType().Name}=\"{value.ToString().Replace("\"", "\\\"")}\"";
            }
        }

        private static string DecodeNameIdentifier(DerObjectIdentifier oid)
        {
            string attributeName = X509Name.RFC2253Symbols[oid] as string;
            return (!string.IsNullOrEmpty(attributeName)) ? attributeName : oid.Id;
        }

        private static string ParsePublicKey(AsymmetricKeyParameter asymmetricKeyParameter)
        {
            try
            {
                if (asymmetricKeyParameter is RsaKeyParameters)
                {
                    RsaKeyParameters rsaKey = (RsaKeyParameters) asymmetricKeyParameter;
                    return $"RSA (key size: {rsaKey.Modulus.BitLength}, exponent: 0x{rsaKey.Exponent:X})";
                }
                else if (asymmetricKeyParameter is ECKeyParameters)
                {
                    ECKeyParameters ecKey = (ECKeyParameters)asymmetricKeyParameter;
                    return $"ECC (key size: {ecKey.Parameters.N.BitLength})";
                }
                else
                {
                    return asymmetricKeyParameter.GetType().Name;
                }
            }
            catch { }
            return string.Empty;
        }

        private static string CreatePemData(byte[] content)
        {
            if ((!ReferenceEquals(content, null)) && (content.Length > 0))
            {
                try
                {
                    using (StringWriter textWriter = new StringWriter())
                    {
                        PemWriter pemWriter = new PemWriter(textWriter);
                        pemWriter.WriteObject(new PemObject("CERTIFICATE", content));
                        textWriter.Flush();
                        return textWriter.ToString();
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string CreateAsn1Dump(Asn1Encodable data)
        {
            if (!ReferenceEquals(data, null))
            {
                try
                {
                    return Asn1Dump.DumpAsString(data);
                }
                catch { }
            }
            return string.Empty;
        }

        private static string AddPadding(string text)
        {
            int length = text.Length;
            int remainder = length % 4;
            if (remainder != 0)
            {
                if (remainder == 1)
                {
                    return AddPadding(string.Concat(text, "0"));
                }
                else
                {
                    return text.PadRight(length + (4 - remainder), '=');
                }
            }
            else
            {
                return text;
            }
        }

        private static void Append(StringBuilder sb, string text)
        {
            if (!string.IsNullOrEmpty(text))
            {
                if (sb.Length > 0)
                {
                    sb.Append(", ").Append(text);
                }
                else
                {
                    sb.Append(text);
                }
            }
        }

        private static string PathLength(int value)
        {
            Debug.Assert(value >= 0);
            return (value == int.MaxValue) ? "unconstrained" : value.ToString();
        }

        private static string X500NameToRFC2253(X509Name name)
        {
            string str = name.ToString(true, X509Name.RFC2253Symbols);
            return (!string.IsNullOrWhiteSpace(str)) ? str.Trim() : string.Empty;
        }

        private static void BringWindowToFront(IntPtr? hwnd)
        {
            if (hwnd.HasValue)
            {
                SetForegroundWindow(hwnd.Value);
            }
        }

        private static string GetBuildDateTime()
        {
            try
            {
                Version version = Assembly.GetExecutingAssembly().GetName().Version;
                return new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                    .Add(new TimeSpan(TimeSpan.TicksPerDay * version.Build + TimeSpan.TicksPerSecond * 2 * version.Revision))
                    .ToString("yyyy-MM-dd");
            }
            catch { }
            return string.Empty;
        }

        public static IEnumerable<T> Once<T>(T item)
        {
            yield return item;
        }

        private class OverrideCursor : IDisposable
        {
            private volatile bool m_disposed = false;

            public OverrideCursor()
            {
                Mouse.OverrideCursor = Cursors.Wait;
            }

            public void Dispose()
            {
                if (!m_disposed)
                {
                    m_disposed = true;
                    Mouse.OverrideCursor = null;
                }
            }
        }

        // ==================================================================
        // Native Methods
        // ==================================================================

        [DllImport("User32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetForegroundWindow(IntPtr hWnd);
    }
}
