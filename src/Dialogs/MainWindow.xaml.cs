/*
 * CertViewer - simple X.509 certificate viewer
 * Copyright (c) 2023 "dEajL3kA" <Cumpoing79@web.de>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions: The above copyright notice and this
 * permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Media;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;

using Microsoft.Win32;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

using CertViewer.Utilities;

using static CertViewer.Utilities.NativeMethods;
using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class MainWindow : Window
    {
        private const int MAX_LENGTH = 128 * 1024 * 1024;
        private const int WM_CLIPBOARDUPDATE = 0x031D;
        private const string BASE_TITLE = "Certificate Viewer";
        private const string UNSPECIFIED = "(Unspecified)";
        private const uint MAX_PASSWORD_ATTEMPTS = 8;

        private static readonly Lazy<IDictionary<DerObjectIdentifier, string>> X509_NAME_ATTRIBUTES = new Lazy<IDictionary<DerObjectIdentifier, string>>(CreateLookup_NameAttributes);
        private static readonly Lazy<IDictionary<DerObjectIdentifier, string>> EXT_KEY_USAGE = new Lazy<IDictionary<DerObjectIdentifier, string>>(CreateLookup_ExtKeyUsage);
        private static readonly Lazy<IDictionary<DerObjectIdentifier, string>> AUTH_INFO_ACCESS = new Lazy<IDictionary<DerObjectIdentifier, string>>(CreateLookup_AuthInfoAccess);
        private static readonly Lazy<IDictionary<ECCurve, string>> ECC_CURVE_NAMES = new Lazy<IDictionary<ECCurve, string>>(CreateLookup_EccCurveNames);

        private static readonly Lazy<Regex> PEM_CERTIFICATE = new Lazy<Regex>(() => new Regex(@"-{3,}?\s*BEGIN\s+CERTIFICATE\s*-{3,}([\t\n\v\f\r\x20-\x7E]+?)-{3,}\s*END\s+CERTIFICATE\s*-{3,}?", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled));
        private static readonly Lazy<Regex> INVALID_BASE64_CHARS = new Lazy<Regex>(() => new Regex(@"[^A-Za-z0-9+/]+", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled));

        private bool m_initialized = false;
        private HashCode m_clipbrdHash = HashCode.Empty;
        private ulong m_clipbrdTick = ulong.MaxValue;
        private IntPtr m_hWndSelf = IntPtr.Zero;

        public X509Certificate Certificate { get; private set; } = null;
        public DigestAlgo DigestAlgorithm { get; private set; } = DigestAlgo.SHA256;
        public bool ReverseNameOrder { get; private set; } = true;
        public bool EnableMonitorClipboard { get; private set; } = true;

        private readonly uint m_processId;
        private readonly IDictionary<TabItem, int> m_tabs;
        private readonly ISet<TabItem> m_tabInitialized;
        private readonly DispatcherTimer m_clipbrdTimer;

        // ==================================================================
        // Constructor
        // ==================================================================

        public MainWindow()
        {
            m_processId = GetCurrentProcessId();
            m_tabInitialized = new HashSet<TabItem>();
            InitializeComponent();
            m_tabs = ItemsToDictionary<TabItem>(TabControl.Items);
            m_clipbrdTimer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher);
            ShowPlaceholder(true);
            LoadConfigurationSettings();
        }

        // ==================================================================
        // Event Handlers
        // ==================================================================

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            HwndSource source = PresentationSource.FromVisual(this) as HwndSource;
            if (IsNotNull(source))
            {
                source.AddHook(WndProc);
                AddClipboardFormatListener(m_hWndSelf = source.Handle);
                m_clipbrdTimer.Tick += OnClipboardChanged;
                m_clipbrdTimer.Interval = TimeSpan.FromMilliseconds(25);
            }
        }

        protected override void OnContentRendered(EventArgs e)
        {
            base.OnContentRendered(e);
            if (!m_initialized)
            {
                MaxHeight = MinHeight = ActualHeight;
                MinWidth = ActualWidth;
                Checkbox_MonitorClipboard.IsChecked = EnableMonitorClipboard;
                Checkbox_StayOnTop.IsChecked = Topmost;
                InitializeContextMenu();
                if ((!ParseCliArguments()) && EnableMonitorClipboard)
                {
                    ParseCertificateFromClipboard();
                }
                m_initialized = true;
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            if (m_hWndSelf != IntPtr.Zero)
            {
                RemoveClipboardFormatListener(m_hWndSelf);
            }
        }

        private void Window_PreviewDragEnter(object sender, DragEventArgs e)
        {
            try
            {
                e.Effects = (IsWindowEnabled(m_hWndSelf) && e.Data.GetDataPresent(DataFormats.FileDrop)) ? DragDropEffects.Copy : DragDropEffects.None;
            }
            catch { }
            e.Handled = true;
        }

        private void Window_PreviewDragLeave(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }

        private void Window_PreviewDrop(object sender, DragEventArgs e)
        {
            try
            {
                if (IsWindowEnabled(m_hWndSelf))
                {
                    string[] droppedFiles = e.Data.GetData(DataFormats.FileDrop) as string[];
                    if (IsNotNull(droppedFiles))
                    {
                        ParseCertificateFile(droppedFiles);
                    }
                }
            }
            catch { }
            e.Handled = true;
        }

        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            foreach (TabItem item in e.AddedItems.OfType<TabItem>())
            {
                if (m_tabInitialized.Add(item))
                {
                    using (OverrideCursor busy = new OverrideCursor())
                    {
                        InitializeTab(GetValueOrDefault(m_tabs, item, int.MaxValue));
                    }
                }
            }
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            switch (msg)
            {
                case WM_CLIPBOARDUPDATE:
                    if (m_initialized && EnableMonitorClipboard)
                    {
                        Restart(m_clipbrdTimer);
                    }
                    handled = true;
                    break;
            }
            return IntPtr.Zero;
        }

        private void OnClipboardChanged(object sender, EventArgs e)
        {
            m_clipbrdTimer.Stop();
            try
            {
                if (EnableMonitorClipboard && (!OwnedWindows.OfType<UserInputDialog>().Any()) && (GetWindowProcessId(GetClipboardOwner()) != m_processId))
                {
                    ParseCertificateFromClipboard();
                }
            }
            catch { }
        }

        private void Button_SubjectDN_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowDistinguishedNameDetails(cert.SubjectDN, "Subject DN");
            }
        }

        private void Button_IssuerDN_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowDistinguishedNameDetails(cert.IssuerDN, "Issuer DN");
            }
        }

        private void Button_Serial_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                try
                {
                    TryCopyToClipboard(ToHexString(cert.SerialNumber));
                    SystemSounds.Beep.Play();
                }
                catch { }
            }
        }
        private void Button_BasicConstraints_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                try
                {
                    int basicConstraints = cert.GetBasicConstraints();
                    TryCopyToClipboard((basicConstraints < 0) ? "End entity certificate (subject is not CA)" : $"CA certificate, max. path length: {DecodePathLenConstraint(basicConstraints)}");
                    SystemSounds.Beep.Play();
                }
                catch { }
            }
        }

        private void Button_PublicKey_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowPublicKeyDetails(cert.GetPublicKey(), cert.CertificateStructure.SubjectPublicKeyInfo);
            }
        }

        private void Button_KeyUsage_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowKeyUsageDetails(cert.GetKeyUsage());
            }
        }

        private void Button_ExtKeyUsage_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowExtKeyUsageDetails(cert.GetExtendedKeyUsage());
            }
        }

        private void Button_SubjAltNames_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowSubjAltNamesDetails(cert.GetSubjectAlternativeNames());
            }
        }

        private void Button_SignAlgo_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowSignatureDetails(cert.SigAlgOid, cert.SigAlgName, cert.GetSignature(), cert.GetSigAlgParams());
            }
        }

        private void Button_Fingerprint_Click(object sender, RoutedEventArgs e)
        {
            Button button = sender as Button;
            if (IsNotNull(button))
            {
                button.ContextMenu.IsOpen = true;
            }
        }

        private void Button_SubjectKeyId_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                try
                {
                    SubjectKeyIdentifier subjectKeyId = GetSubjectKeyIdentifier(cert);
                    if (IsNotNull(subjectKeyId))
                    {
                        TryCopyToClipboard(ParseSubjectKeyIdentifier(subjectKeyId));
                        SystemSounds.Beep.Play();
                    }
                }
                catch { }
            }
        }

        private void Button_AuthorityKeyId_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                try
                {
                    AuthorityKeyIdentifier authorityKeyId = GetAuthorityKeyIdentifier(cert);
                    if (IsNotNull(authorityKeyId))
                    {
                        TryCopyToClipboard(ParseAuthorityKeyIdentifier(authorityKeyId));
                        SystemSounds.Beep.Play();
                    }
                }
                catch { }
            }
        }

        private void Button_CrlDistPoint_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowCrlDistPointDetails(GetCrlDistributionPoints(cert));
            }
        }

        private void Button_AuthorityInformation_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowAuthorityInformationDetails(GetAuthorityInformationAccess(cert));
            }
        }

        private void Button_CertPolicies_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowCertPolicyDetails(GetCertificatePolicies(cert));
            }
        }

        private void MenuItem_DigestAlgo_Checked(object sender, RoutedEventArgs e)
        {
            MenuItem item;
            if (IsNotNull(item = sender as MenuItem))
            {
                DigestAlgo? algo = item.Tag as DigestAlgo?;
                if ((algo.HasValue) && (!algo.Value.Equals(DigestAlgorithm)))
                {
                    DigestAlgorithm = algo.Value;
                    ContextMenu menu;
                    if (IsNotNull(menu = item.Parent as ContextMenu))
                    {
                        foreach (object other in menu.Items)
                        {
                            MenuItem otherItem;
                            if (IsNotNull(otherItem = other as MenuItem))
                            {
                                DigestAlgo? otherAlgo = otherItem.Tag as DigestAlgo?;
                                if ((!otherAlgo.HasValue) || (!otherAlgo.Value.Equals(algo.Value)))
                                {
                                    otherItem.IsChecked = false;
                                }
                            }
                        }
                    }
                    UpdateFingerprintValue();
                }
            }
        }

        private void MenuItem_DigestAlgo_Unchecked(object sender, RoutedEventArgs e)
        {
            MenuItem item;
            if (IsNotNull(item = sender as MenuItem))
            {
                DigestAlgo? algo = item.Tag as DigestAlgo?;
                if (algo.HasValue && algo.Value.Equals(DigestAlgorithm))
                {
                    item.IsChecked = true;
                }
            }
        }

        private void MenuItem_CopyDigest_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                try
                {
                    string digestHex = ToHexString(CalculateDigest(cert));
                    TryCopyToClipboard($"{Enum.GetName(typeof(DigestAlgo), DigestAlgorithm)}={digestHex}");
                    SystemSounds.Beep.Play();
                }
                catch { }
            }
        }

        private void Checkbox_StayOnTop_Clicked(object sender, RoutedEventArgs e)
        {
            CheckBox checkbox = sender as CheckBox;
            if (IsNotNull(checkbox))
            {
                Topmost = checkbox.IsChecked.GetValueOrDefault(false);
            }
        }

        private void Checkbox_MonitorClipboard_Clicked(object sender, RoutedEventArgs e)
        {
            CheckBox checkbox = sender as CheckBox;
            if (IsNotNull(checkbox))
            {
                EnableMonitorClipboard = checkbox.IsChecked.GetValueOrDefault(false);
            }
        }

        private void Clear_Clicked(object sender, RoutedEventArgs e)
        {
            m_clipbrdHash = HashCode.Empty;
            Certificate = null;
            Title = BASE_TITLE;
            TextBox_Asn1Data.Text = TextBox_BasicConstraints.Text = TextBox_Fingerprint.Text = 
                TextBox_ExtKeyUsage.Text = TextBox_Issuer.Text = TextBox_KeyUsage.Text = TextBox_NotAfter.Text =
                TextBox_NotBefore.Text = TextBox_PemData.Text = TextBox_PublicKey.Text = TextBox_Serial.Text =
                TextBox_SignAlgo.Text = TextBox_SubjAltNames.Text = TextBox_Subject.Text =
                TextBox_AuthorityKeyId.Text = TextBox_SubjectKeyId.Text = TextBox_CrlDistPoint.Text =
                TextBox_CertPolicies.Text = TextBox_AuthorityInformation.Text = string.Empty;
            Image_NotBefore_Valid.Visibility = Image_NotBefore_Expired.Visibility =
                Image_NotAfter_Valid.Visibility = Image_NotAfter_Expired.Visibility = Visibility.Hidden;
            ShowPlaceholder(true);
            Tab_Extensions.IsEnabled = Tab_Asn1Data.IsEnabled = Tab_PemData.IsEnabled = false;
            TabControl.SelectedItem = Tab_CertInfo;
        }

        private void Label_ErrorText_MouseDown(object sender, MouseButtonEventArgs e)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(Label_ErrorText.Content as string);
            sb.AppendLine(Label_ErrorText.ToolTip as string);
            try
            {
                TryCopyToClipboard(sb.ToString());
                SystemSounds.Beep.Play();
            }
            catch { }
            HideErrorText();
        }

        private void Image_Placeholder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount == 2))
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.Filter = "Certificate Files|*.pem;*.der;*.cer;*.crt;*.p12;*.pfx|All Files|*.*";
                if (openFileDialog.ShowDialog(this).GetValueOrDefault(false))
                {
                    ParseCertificateFile(openFileDialog.FileName);
                }
            }
        }

        private void Label_Asn1Data_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount > 0))
            {
                try
                {
                    TryCopyToClipboard(TextBox_Asn1Data.Text);
                    SystemSounds.Beep.Play();
                }
                catch { }
            }
        }

        private void Label_PemData_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount > 0))
            {
                try
                {
                    TryCopyToClipboard(TextBox_PemData.Text);
                    SystemSounds.Beep.Play();
                }
                catch { }
            }
        }

        private void Image_About_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount > 0))
            {
                AboutDialog aboutDialog = new AboutDialog() { Owner = this };
                aboutDialog.ShowDialog();
            }
        }

        // ==================================================================
        // Internal Methods
        // ==================================================================

        private void LoadConfigurationSettings()
        {
            try
            {
                Configuration configuration = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                KeyValueConfigurationCollection settings = configuration.AppSettings.Settings;
                GetSettingsValue(settings, "DigestAlgorithm", value =>
                {
                    DigestAlgo digestAlgo;
                    if (Enum.TryParse(value, true, out digestAlgo))
                    {
                        DigestAlgorithm = digestAlgo;
                    }
                });
                GetSettingsValue(settings, "Topmost", value =>
                {
                    bool booleanValue;
                    if (bool.TryParse(value, out booleanValue))
                    {
                        Topmost = booleanValue;
                    }
                });
                GetSettingsValue(settings, "MonitorClipboard", value =>
                {
                    bool booleanValue;
                    if (bool.TryParse(value, out booleanValue))
                    {
                        EnableMonitorClipboard = booleanValue;
                    }
                });
                GetSettingsValue(settings, "ReverseNameOrder", value =>
                {
                    bool booleanValue;
                    if (bool.TryParse(value, out booleanValue))
                    {
                        ReverseNameOrder = booleanValue;
                    }
                });
            }
            catch { }
        }

        private void InitializeContextMenu()
        {
            try
            {
                foreach (MenuItem item in Button_Fingerprint.ContextMenu.Items.OfType<MenuItem>())
                {
                    DigestAlgo? algorithm = item.Tag as DigestAlgo?;
                    item.IsChecked = (algorithm.HasValue) && algorithm.Value.Equals(DigestAlgorithm);
                }
            }
            catch { }
        }

        private bool ParseCliArguments()
        {
            try
            {
                string[] commandLineArgs = FilterCliArguments(Environment.GetCommandLineArgs().Skip(1)).ToArray();
                if (IsNotEmpty(commandLineArgs))
                {
                    ParseCertificateFile(commandLineArgs);
                    return true;
                }
            }
            catch { }
            return false;
        }

        private bool ParseCertificateFromClipboard()
        {
            using (OverrideCursor busy = new OverrideCursor())
            {
                HideErrorText();
                try
                {
                    string text;
                    if (IsNotEmpty(text = TryPasteFromClipboard()))
                    {
                        HashCode currentHash = HashCode.Compute(text.Trim());
                        ulong ticks = GetTickCount64();
                        if ((!m_clipbrdHash.Equals(currentHash)) || (ticks < m_clipbrdTick) || ((ticks - m_clipbrdTick) >= 15000))
                        {
                            m_clipbrdHash = currentHash;
                            m_clipbrdTick = ticks;
                            Match match = PEM_CERTIFICATE.Value.Match(text);
                            while (match.Success)
                            {
                                Title = $"Clipboard \u2013 {BASE_TITLE}";
                                if (ParseCertificateData(match.Groups[1].Value, busy))
                                {
                                    return true;
                                }
                                match = match.NextMatch();
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    TabControl.SelectedItem = Tab_CertInfo;
                    Certificate = null;
                    ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}", e.ToString());
                }
            }
            return false;
        }

        private bool ParseCertificateFile(params string[] fileNames)
        {
            using (OverrideCursor busy = new OverrideCursor())
            {
                HideErrorText();
                if (IsNotEmpty(fileNames))
                {
                    try
                    {
                        foreach (string fileName in fileNames)
                        {
                            byte[] data = ReadFileContents(fileName, MAX_LENGTH);
                            if (IsNotEmpty(data))
                            {
                                Title = $"{GetBaseName(fileName)} \u2013 {BASE_TITLE}";
                                m_clipbrdHash = HashCode.Empty;
                                Match match = PEM_CERTIFICATE.Value.Match(Encoding.UTF8.GetString(data));
                                while (match.Success)
                                {
                                    if (ParseCertificateData(match.Groups[1].Value, busy))
                                    {
                                        return true;
                                    }
                                    match = match.NextMatch();
                                }
                                if (ParseCertificateData(data, busy))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        TabControl.SelectedItem = Tab_CertInfo;
                        Certificate = null;
                        ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}", e.ToString());
                    }
                }
            }
            return false;
        }

        private bool ParseCertificateData(string base64text, OverrideCursor busy)
        {
            try
            {
                if (IsNotEmpty(base64text))
                {
                    base64text = INVALID_BASE64_CHARS.Value.Replace(base64text, string.Empty);
                    if (base64text.Length > 0)
                    {
                        return ParseCertificateData(Convert.FromBase64String(AddPadding(base64text)), busy);
                    }
                }
            }
            catch (Exception e)
            {
                TabControl.SelectedItem = Tab_CertInfo;
                Certificate = null;
                ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}", e.ToString());
            }
            return false;
        }

        private bool ParseCertificateData(byte[] data, OverrideCursor busy)
        {
            bool success = false;
            try
            {
                X509Certificate cert = ReadCertificateFile(data, busy);
                m_tabInitialized.Clear();
                if (success = IsNotNull(Certificate = cert))
                {
                    string subjectDN = EscapeString(X500NameToRFC2253(cert.SubjectDN, ReverseNameOrder), false);
                    SetText(TextBox_Subject, DefaultString(subjectDN, UNSPECIFIED));
                    Button_SubjectDN.IsEnabled = IsNotEmpty(subjectDN);
                    string issuerDN = EscapeString(X500NameToRFC2253(cert.IssuerDN, ReverseNameOrder), false);
                    SetText(TextBox_Issuer, DefaultString(issuerDN, UNSPECIFIED));
                    Button_IssuerDN.IsEnabled = IsNotEmpty(issuerDN);
                    SetText(TextBox_Serial, $"0x{ToHexString(cert.SerialNumber)}");
                    DateTime notBeforeUtc = cert.NotBefore.ToUniversalTime();
                    DateTime notAfterUtc = cert.NotAfter.ToUniversalTime();
                    SetText(TextBox_NotBefore, notBeforeUtc.ToString("yyyy-MM-dd HH\\:mm\\:ss", CultureInfo.InvariantCulture));
                    SetText(TextBox_NotAfter, notAfterUtc.ToString("yyyy-MM-dd HH\\:mm\\:ss", CultureInfo.InvariantCulture));
                    DateTime now = DateTime.UtcNow;
                    ShowStatusIcon(notBeforeUtc < now, Image_NotBefore_Valid, Image_NotBefore_Expired);
                    ShowStatusIcon(notAfterUtc > now, Image_NotAfter_Valid, Image_NotAfter_Expired);
                    string subjectAlternativeNames = ParseSubjectAlternativeNames(cert.GetSubjectAlternativeNames());
                    SetText(TextBox_SubjAltNames, DefaultString(subjectAlternativeNames, UNSPECIFIED));
                    Button_SubjAltNames.IsEnabled = IsNotEmpty(subjectAlternativeNames);
                    string publicKeyInfo = ParsePublicKey(cert.GetPublicKey());
                    SetText(TextBox_PublicKey, DefaultString(publicKeyInfo, UNSPECIFIED));
                    Button_PublicKey.IsEnabled = IsNotEmpty(publicKeyInfo);
                    string signatureInfo = ParseSignatureInfo(cert.SigAlgName, cert.CertificateStructure.Signature);
                    SetText(TextBox_SignAlgo, DefaultString(signatureInfo, UNSPECIFIED));
                    Button_SignAlgo.IsEnabled = IsNotEmpty(signatureInfo);
                    SetText(TextBox_Fingerprint, ToHexString(CalculateDigest(cert)));
                    m_tabInitialized.Add(Tab_CertInfo);
                    TabControl.SelectedItem = Tab_CertInfo;
                    ShowPlaceholder(false);
                    BringWindowToFront(m_hWndSelf);
                }
                else
                {
                    TabControl.SelectedItem = Tab_CertInfo;
                    Certificate = null;
                    ShowPlaceholder(true, "Error: Input does not contain a valid X.509 certificate!");
                }
            }
            catch(Exception e)
            {
                TabControl.SelectedItem = Tab_CertInfo;
                Certificate = null;
                ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}", e.ToString());
            }
            return success;
        }

        private void InitializeTab(int selectedTabIndex)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                try
                {
                    switch (selectedTabIndex)
                    {
                        case 1:
                            int basicConstraints = cert.GetBasicConstraints();
                            SetText(TextBox_BasicConstraints, (basicConstraints < 0) ? "End entity certificate (subject is not CA)" : $"CA certificate, max. path length: {DecodePathLenConstraint(basicConstraints)}");
                            string keyUsage = ParseKeyUsage(cert.GetKeyUsage());
                            SetText(TextBox_KeyUsage, DefaultString(keyUsage, UNSPECIFIED));
                            Button_KeyUsage.IsEnabled = IsNotEmpty(keyUsage);
                            string extKeyUsage = ParseExtendedKeyUsage(cert.GetExtendedKeyUsage());
                            SetText(TextBox_ExtKeyUsage, DefaultString(extKeyUsage, UNSPECIFIED));
                            Button_ExtKeyUsage.IsEnabled = IsNotEmpty(extKeyUsage);
                            string subjectKeyId = ParseSubjectKeyIdentifier(GetSubjectKeyIdentifier(cert));
                            SetText(TextBox_SubjectKeyId, DefaultString(subjectKeyId, UNSPECIFIED));
                            Button_SubjectKeyId.IsEnabled = IsNotEmpty(subjectKeyId);
                            string authorityKeyId = ParseAuthorityKeyIdentifier(GetAuthorityKeyIdentifier(cert));
                            SetText(TextBox_AuthorityKeyId, DefaultString(authorityKeyId, UNSPECIFIED));
                            Button_AuthorityKeyId.IsEnabled = IsNotEmpty(authorityKeyId);
                            string crlDistributionPoints = ParseCrlDistributionPoints(GetCrlDistributionPoints(cert));
                            SetText(TextBox_CrlDistPoint, DefaultString(crlDistributionPoints, UNSPECIFIED));
                            Button_CrlDistPoint.IsEnabled = IsNotEmpty(crlDistributionPoints);
                            string authorityInformationAccess = ParseAuthorityInformationAccess(GetAuthorityInformationAccess(cert));
                            SetText(TextBox_AuthorityInformation, DefaultString(authorityInformationAccess, UNSPECIFIED));
                            Button_AuthorityInformation.IsEnabled = IsNotEmpty(authorityInformationAccess);
                            string certificatePolicies = ParseCertificatePolicies(GetCertificatePolicies(cert));
                            SetText(TextBox_CertPolicies, DefaultString(certificatePolicies, UNSPECIFIED));
                            Button_CertPolicies.IsEnabled = IsNotEmpty(certificatePolicies);
                            break;
                        case 2:
                            SetText(TextBox_Asn1Data, CreateAsn1Dump(cert.CertificateStructure), false);
                            break;
                        case 3:
                            SetText(TextBox_PemData, CreatePemData("CERTIFICATE", cert.CertificateStructure), false);
                            break;
                    }
                }
                catch { }
            }
        }

        private X509Certificate ReadCertificateFile(byte[] data, OverrideCursor busy)
        {
            if (IsNotEmpty(data))
            {
                X509Certificate cert;
                try
                {
                    if (IsNotNull(cert = new X509CertificateParser().ReadCertificate(data)))
                    {
                        return cert;
                    }
                }
                catch (Exception e) when ((e is IOException) || (e is CertificateException))
                {
                    if (IsNotNull(cert = ReadPkcs12File(data, busy)))
                    {
                        return cert;
                    }
                    throw;
                }
                return ReadPkcs12File(data, busy);
            }
            return null;
        }

        private X509Certificate ReadPkcs12File(byte[] data, OverrideCursor busy, string password = null, uint retry = 0)
        {
            if (IsNotEmpty(data))
            {
                try
                {
                    Pkcs12Store pkcs12Store = new Pkcs12StoreBuilder().Build();
                    using (MemoryStream stream = new MemoryStream(data, false))
                    {
                        pkcs12Store.Load(stream, IsNotEmpty(password) ? password.ToCharArray() : Array.Empty<char>());
                        foreach (string alias in SelectCertificate(pkcs12Store.Aliases, busy))
                        {
                            X509CertificateEntry entry;
                            if (IsNotNull(entry = pkcs12Store.GetCertificate(alias)))
                            {
                                X509Certificate cert;
                                if (IsNotNull(cert = entry.Certificate))
                                {
                                    return cert;
                                }
                            }
                        }
                    }
                }
                catch (IOException e) when (e.Message.IndexOf("wrong password", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (retry < MAX_PASSWORD_ATTEMPTS)
                    {
                        PasswordDialog dialog = new PasswordDialog(password, retry + 1U, MAX_PASSWORD_ATTEMPTS) { Owner = this, Title = "PKCS#12 Password" };
                        if (dialog.ShowDialog(busy).GetValueOrDefault(false))
                        {
                            return ReadPkcs12File(data, busy, dialog.Password, retry + 1U);
                        }
                    }
                    else
                    {
                        throw; /*too many attempts*/
                    }
                }
                catch { }
            }
            return ReadJksFile(data, busy);
        }

        private X509Certificate ReadJksFile(byte[] data, OverrideCursor busy, string password = null, uint retry = 0)
        {
            if (IsNotEmpty(data))
            {
                try
                {
                    JksStore jksStore = new JksStore();
                    bool probeResult;
                    using (MemoryStream stream = new MemoryStream(data, false))
                    {
                        probeResult = jksStore.Probe(stream);
                    }
                    if (probeResult)
                    {
                        using (MemoryStream stream = new MemoryStream(data, false))
                        {
                            jksStore.Load(stream, IsNotEmpty(password) ? password.ToCharArray() : Array.Empty<char>());
                            foreach (string alias in SelectCertificate(jksStore.Aliases, busy))
                            {
                                X509Certificate cert;
                                if (IsNotNull(cert = jksStore.GetCertificate(alias)))
                                {
                                    return cert;
                                }
                            }
                        }
                    }
                }
                catch (IOException e) when (e.Message.IndexOf("password incorrect", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (retry < MAX_PASSWORD_ATTEMPTS)
                    {
                        PasswordDialog dialog = new PasswordDialog(password, retry + 1U, MAX_PASSWORD_ATTEMPTS) { Owner = this, Title = "JKS Password" };
                        if (dialog.ShowDialog(busy).GetValueOrDefault(false))
                        {
                            return ReadJksFile(data, busy, dialog.Password, retry + 1U);
                        }
                    }
                    else
                    {
                        throw; /*too many attempts*/
                    }
                }
                //catch { }
            }
            return null; /*finally giving up*/
        }

        private IEnumerable<string> SelectCertificate(IEnumerable<string> aliases, OverrideCursor busy)
        {
            if (IsNotEmpty(aliases))
            {
                if (aliases.Skip(1).Any())
                {
                    ItemSelection dialog = new ItemSelection(aliases) { Owner = this, Title = "Choose Certificate" };
                    if (dialog.ShowDialog(busy).GetValueOrDefault(false))
                    {
                        string alias;
                        if (IsNotEmpty(alias = dialog.SelectedItem))
                        {
                            yield return alias;
                        }
                    }
                }
                else
                {
                    yield return aliases.First();
                }
            }
        }

        private void ShowDistinguishedNameDetails(X509Name name, string title)
        {
            if (IsNotNull(name) && IsNotEmpty(title))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IList<DerObjectIdentifier> oidList = name.GetOidList();
                    IList<string> valList = name.GetValueList();
                    if (IsNotEmpty(oidList) && IsNotEmpty(valList))
                    {
                        IDictionary<DerObjectIdentifier, string> oidSymbols = X509_NAME_ATTRIBUTES.Value;
                        IEnumerable<KeyValuePair<string, string>> items = oidList.Select(oid => GetValueOrDefault(oidSymbols, oid, oid.Id))
                                .Zip(valList, (key, value) => new KeyValuePair<string, string>(key, value));
                        if (items.Any())
                        {
                            DetailsView viewer = new DetailsView(ReverseNameOrder ? items.Reverse() : items) { Owner = this, Title = title };
                            viewer.ShowDialog(busy);
                        }
                    }
                }
            }
        }

        private void ShowPublicKeyDetails(AsymmetricKeyParameter asymmetricKeyParameter, SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            if (IsNotNull(asymmetricKeyParameter) && IsNotNull(subjectPublicKeyInfo))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    List<KeyValuePair<string, string>> items = new List<KeyValuePair<string, string>>(8);
                    try
                    {
                        items.Add(new KeyValuePair<string, string>("oid", subjectPublicKeyInfo.AlgorithmID.Algorithm.Id));
                        const string ALGORITHM_NAME = "algorithm";
                        if (asymmetricKeyParameter is ElGamalKeyParameters egKey)
                        {
                            items.Add(new KeyValuePair<string, string>(ALGORITHM_NAME, "ElGamal encryption"));
                            ElGamalParameters param = egKey.Parameters;
                            items.Add(new KeyValuePair<string, string>("G", ToHexString(param.G)));
                            items.Add(new KeyValuePair<string, string>("P", ToHexString(param.P)));
                            items.Add(new KeyValuePair<string, string>("L", $"{param.L:X}"));
                        }
                        else if (asymmetricKeyParameter is DsaPublicKeyParameters dsaKey)
                        {
                            items.Add(new KeyValuePair<string, string>(ALGORITHM_NAME, "DSA (Digital Signature Algorithm)"));
                            DsaParameters param = dsaKey.Parameters;
                            items.Add(new KeyValuePair<string, string>("G", ToHexString(param.G)));
                            items.Add(new KeyValuePair<string, string>("P", ToHexString(param.P)));
                            items.Add(new KeyValuePair<string, string>("Q", ToHexString(param.Q)));
                        }
                        else if (asymmetricKeyParameter is RsaKeyParameters rsaKey)
                        {
                            items.Add(new KeyValuePair<string, string>(ALGORITHM_NAME, "RSA (Rivest–Shamir–Adleman)"));
                            items.Add(new KeyValuePair<string, string>("exponent", ToHexString(rsaKey.Exponent)));
                            items.Add(new KeyValuePair<string, string>("modulus", ToHexString(rsaKey.Modulus)));
                        }
                        else if (asymmetricKeyParameter is ECPublicKeyParameters eccKey)
                        {
                            items.Add(new KeyValuePair<string, string>(ALGORITHM_NAME, "ECC (Elliptic-Curve Cryptography)"));
                            string curve = GetValueOrDefault(ECC_CURVE_NAMES.Value, eccKey.Parameters.Curve, string.Empty);
                            items.Add(new KeyValuePair<string, string>("curve", IsNotEmpty(curve) ? $"{curve} ({eccKey.PublicKeyParamSet.Id})" : eccKey.PublicKeyParamSet.Id));
                            items.Add(new KeyValuePair<string, string>("Q.x", ToHexString(eccKey.Q.AffineXCoord.ToBigInteger())));
                            items.Add(new KeyValuePair<string, string>("Q.y", ToHexString(eccKey.Q.AffineYCoord.ToBigInteger())));
                            ECDomainParameters param = eccKey.Parameters;
                            items.Add(new KeyValuePair<string, string>("p", ToHexString(param.Curve.Field.Characteristic)));
                            items.Add(new KeyValuePair<string, string>("a", ToHexString(param.Curve.A.ToBigInteger())));
                            items.Add(new KeyValuePair<string, string>("b", ToHexString(param.Curve.B.ToBigInteger())));
                            items.Add(new KeyValuePair<string, string>("G.x", ToHexString(param.G.AffineXCoord.ToBigInteger())));
                            items.Add(new KeyValuePair<string, string>("G.y", ToHexString(param.G.AffineYCoord.ToBigInteger())));
                            items.Add(new KeyValuePair<string, string>("n", ToHexString(param.N)));
                            items.Add(new KeyValuePair<string, string>("h", ToHexString(param.H)));
                        }
                        else
                        {
                            items.Add(new KeyValuePair<string, string>("value", ToHexString(subjectPublicKeyInfo.GetEncoded())));
                        }
                        Asn1Encodable parameters;
                        if ((items.Count < 5) && IsNotNull(parameters = subjectPublicKeyInfo.AlgorithmID.Parameters))
                        {
                            items.Add(new KeyValuePair<string, string>("parameter", ToHexString(parameters.GetEncoded())));
                        }
                    }
                    catch { }
                    DetailsView viewer = new DetailsView(items, CreateAsn1Dump(subjectPublicKeyInfo), CreatePemData("PUBLIC KEY", subjectPublicKeyInfo)) { Owner = this, Title = "Public Key" };
                    viewer.ShowDialog(busy);
                }
            }
        }

        private void ShowSignatureDetails(string sigAlgOid, string sigAlgName, byte[] signature, byte[] sigParameters)
        {
            if (IsNotEmpty(sigAlgOid) && IsNotEmpty(sigAlgName) && IsNotEmpty(signature))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    List<KeyValuePair<string, string>> items = new List<KeyValuePair<string, string>>(8);
                    try
                    {
                        items.Add(new KeyValuePair<string, string>("oid", sigAlgOid));
                        items.Add(new KeyValuePair<string, string>("algorithm", sigAlgName));
                        items.Add(new KeyValuePair<string, string>("value", ToHexString(signature)));
                        if (IsNotEmpty(sigParameters))
                        {
                            items.Add(new KeyValuePair<string, string>("parameter", ToHexString(sigParameters)));
                        }
                    }
                    catch { }
                    DetailsView viewer = new DetailsView(items) { Owner = this, Title = "Signature" };
                    viewer.ShowDialog(busy);
                }
            }
        }

        private void ShowKeyUsageDetails(bool[] keyUsage)
        {
            if (IsNotNull(keyUsage))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IEnumerable<KeyValuePair<string, string>> items = keyUsage.Select((value, index) => value ? DecodeKeyUsage(index) : string.Empty)
                        .Where(item => IsNotEmpty(item))
                        .Select(item => new KeyValuePair<string, string>("keyUsage", item));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = "Key Usage" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }

        private void ShowExtKeyUsageDetails(IList<DerObjectIdentifier> extKeyUsage)
        {
            if (IsNotNull(extKeyUsage))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IDictionary<DerObjectIdentifier, string> lookup = EXT_KEY_USAGE.Value;
                    IEnumerable<KeyValuePair<string, string>> items = extKeyUsage.Select(oid => GetValueOrDefault(lookup, oid, oid.Id))
                        .Select(item => new KeyValuePair<string, string>("extKeyUsage", item));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = "Extended Key Usage" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }

        private void ShowSubjAltNamesDetails(IList<IList<object>> subjectAlternativeNames)
        {
            if (IsNotNull(subjectAlternativeNames))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IEnumerable<KeyValuePair<string, string>> items = subjectAlternativeNames.Where(item => item.Count >= 2)
                        .Select(item => new KeyValuePair<string, string>(DecodeGeneralNameType(item[0] as int?), item[1] as string))
                        .Where(item => IsNotEmpty(item.Key) && IsNotEmpty(item.Value));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = "Subject Alternative Names" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }

        private void ShowAuthorityInformationDetails(AuthorityInformationAccess authorityInformationAccess)
        {
            if (IsNotNull(authorityInformationAccess))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IDictionary<DerObjectIdentifier, string> method = AUTH_INFO_ACCESS.Value;
                    IEnumerable<KeyValuePair<string, string>> items = authorityInformationAccess.GetAccessDescriptions()
                        .Select(descr => Tuple.Create(GetValueOrDefault(method, descr.AccessMethod, string.Empty), descr.AccessLocation))
                        .Where(descr => IsNotEmpty(descr.Item1) && IsNotNull(descr.Item2))
                        .Select(descr => Tuple.Create(descr.Item1, DecodeGeneralNameType(descr.Item2.TagNo), DecodeGeneralNameValue(descr.Item2.Name)))
                        .Where(descr => IsNotEmpty(descr.Item2) && IsNotNull(descr.Item3))
                        .Select(descr => new KeyValuePair<string, string>($"{descr.Item1}.{descr.Item2}", descr.Item3));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items, CreateAsn1Dump(authorityInformationAccess)) { Owner = this, Title = "Authority Information Access" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }
        private void ShowCertPolicyDetails(CertificatePolicies certificatePolicies)
        {
            if (IsNotNull(certificatePolicies))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IEnumerable<KeyValuePair<string, string>> items = certificatePolicies.GetPolicyInformation()
                        .SelectMany((info, index) => DecodePolicyInformation(info).Select(item => Tuple.Create(index, item.Item1, item.Item2)))
                        .Select(item => new KeyValuePair<string, string>($"policy[{item.Item1}].{item.Item2}", item.Item3));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items, CreateAsn1Dump(certificatePolicies)) { Owner = this, Title = "Certificate Policies" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }

        private void ShowCrlDistPointDetails(CrlDistPoint crlDistPoints)
        {
            if (IsNotNull(crlDistPoints))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    IEnumerable<KeyValuePair<string, string>> items = crlDistPoints.GetDistributionPoints()
                        .Select(point => point.DistributionPointName)
                        .Where(point => IsNotNull(point) && (point.Type == 0))
                        .Select(point => point.Name)
                        .OfType<GeneralNames>()
                        .SelectMany((names, index) => names.GetNames().Select(name => Tuple.Create(index, name.TagNo, name.Name)))
                        .Select(name => Tuple.Create(name.Item1, DecodeGeneralNameType(name.Item2), DecodeGeneralNameValue(name.Item3)))
                        .Where(name => IsNotEmpty(name.Item2) && IsNotEmpty(name.Item3))
                        .Select(name => new KeyValuePair<string, string>($"distPoint[{name.Item1}].{name.Item2}", name.Item3));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items, CreateAsn1Dump(crlDistPoints)) { Owner = this, Title = "CRL Distribution Points" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }

        private byte[] CalculateDigest(X509Certificate cert)
        {
            if (IsNotNull(cert))
            {
                try
                {
                    switch (DigestAlgorithm)
                    {
                        case DigestAlgo.MD5:        return DigestUtilities.CalculateDigest("MD5",         cert.GetEncoded());
                        case DigestAlgo.RIPEMD128:  return DigestUtilities.CalculateDigest("RIPEMD-128",  cert.GetEncoded());
                        case DigestAlgo.RIPEMD160:  return DigestUtilities.CalculateDigest("RIPEMD-160",  cert.GetEncoded());
                        case DigestAlgo.RIPEMD256:  return DigestUtilities.CalculateDigest("RIPEMD-256",  cert.GetEncoded());
                        case DigestAlgo.SHA1:       return DigestUtilities.CalculateDigest("SHA-1",       cert.GetEncoded());
                        case DigestAlgo.SHA224:     return DigestUtilities.CalculateDigest("SHA-224",     cert.GetEncoded());
                        case DigestAlgo.SHA256:     return DigestUtilities.CalculateDigest("SHA-256",     cert.GetEncoded());
                        case DigestAlgo.SHA3_224:   return DigestUtilities.CalculateDigest("SHA3-224",    cert.GetEncoded());
                        case DigestAlgo.SHA3_256:   return DigestUtilities.CalculateDigest("SHA3-256",    cert.GetEncoded());
                        case DigestAlgo.BLAKE2_160: return DigestUtilities.CalculateDigest("BLAKE2B-160", cert.GetEncoded());
                        case DigestAlgo.BLAKE2_256: return DigestUtilities.CalculateDigest("BLAKE2B-256", cert.GetEncoded());
                        case DigestAlgo.BLAKE3:     return DigestUtilities.CalculateDigest("BLAKE3-256",  cert.GetEncoded());
                    }
                }
                catch { }
            }
            return Array.Empty<byte>();
        }

        private void UpdateFingerprintValue()
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                SetText(TextBox_Fingerprint, ToHexString(CalculateDigest(cert)));
            }
        }

        private void ShowPlaceholder(bool show, string placeholderText = null, string details = null)
        {
            Tab_Extensions.IsEnabled = Tab_PemData.IsEnabled = Tab_Asn1Data.IsEnabled = show ? false : true;
            Panel_Placeholder.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            Panel_CertInfo.Visibility = show ? Visibility.Hidden : Visibility.Visible;
            Label_ErrorText.Visibility = IsNotEmpty(placeholderText) ? Visibility.Visible : Visibility.Hidden;
            Label_ErrorText.Content = DefaultString(placeholderText);
            Label_ErrorText.ToolTip = IsNotEmpty(details) ? details : null;
            Keyboard.ClearFocus();
            FocusManager.SetFocusedElement(this, null);
        }

        private static void ShowStatusIcon(bool show, FrameworkElement icon1, FrameworkElement icon2)
        {
            icon1.Visibility = show ? Visibility.Visible : Visibility.Hidden;
            icon2.Visibility = show ? Visibility.Hidden : Visibility.Visible;
        }

        private void HideErrorText()
        {
            if (Label_ErrorText.Visibility == Visibility.Visible)
            {
                Label_ErrorText.Content = string.Empty;
                Label_ErrorText.Visibility = Visibility.Hidden;
            }
        }

        // ==================================================================
        // Utility Methods
        // ==================================================================

        private static IDictionary<DerObjectIdentifier, string> CreateLookup_NameAttributes()
        {
            Dictionary<DerObjectIdentifier, string> builder = new Dictionary<DerObjectIdentifier, string>(X509Name.DefaultSymbols)
            {
                { X509Name.Name,                       "name"                                           },
                { X509Name.DmdName,                    "dmdName"                                        },
                { X509Name.OrganizationIdentifier,     "organizationIdentifier"                         },
                { MakeOid("1.3.6.1.4.1.311.60.2.1.1"), "jurisdictionOfIncorporationLocalityName"        },
                { MakeOid("1.3.6.1.4.1.311.60.2.1.2"), "jurisdictionOfIncorporationStateOrProvinceName" },
                { MakeOid("1.3.6.1.4.1.311.60.2.1.3"), "jurisdictionOfIncorporationCountryName"         }
            };
            return CollectionUtilities.ReadOnly(builder);
        }

        private static IDictionary<DerObjectIdentifier, string> CreateLookup_ExtKeyUsage()
        {
            Dictionary<DerObjectIdentifier, string> builder = new Dictionary<DerObjectIdentifier, string>
            {
                { KeyPurposeID.id_kp_capwapAC,             "capwapAC"             },
                { KeyPurposeID.id_kp_capwapWTP,            "capwapWTP"            },
                { KeyPurposeID.id_kp_clientAuth,           "clientAuth"           },
                { KeyPurposeID.id_kp_cmcCA,                "cmcCA"                },
                { KeyPurposeID.id_kp_cmcRA,                "cmcRA"                },
                { KeyPurposeID.id_kp_cmKGA,                "cmKGA"                },
                { KeyPurposeID.id_kp_codeSigning,          "codeSigning"          },
                { KeyPurposeID.id_kp_dvcs,                 "dvcs"                 },
                { KeyPurposeID.id_kp_eapOverLAN,           "eapOverLAN"           },
                { KeyPurposeID.id_kp_eapOverPPP,           "eapOverPPP"           },
                { KeyPurposeID.id_kp_emailProtection,      "emailProtection"      },
                { KeyPurposeID.id_kp_ipsecEndSystem,       "ipsecEndSystem"       },
                { KeyPurposeID.id_kp_ipsecIKE,             "ipsecIKE"             },
                { KeyPurposeID.id_kp_ipsecTunnel,          "ipsecTunnel"          },
                { KeyPurposeID.id_kp_ipsecUser,            "ipsecUser"            },
                { KeyPurposeID.id_kp_macAddress,           "macAddress"           },
                { KeyPurposeID.id_kp_msSGC,                "msSGC"                },
                { KeyPurposeID.id_kp_OCSPSigning,          "ocspSigning"          },
                { KeyPurposeID.id_kp_sbgpCertAAServerAuth, "sbgpCertAAServerAuth" },
                { KeyPurposeID.id_kp_scvpClient,           "scvpClient"           },
                { KeyPurposeID.id_kp_scvpServer,           "scvpServer"           },
                { KeyPurposeID.id_kp_scvp_responder,       "scvp_responder"       },
                { KeyPurposeID.id_kp_serverAuth,           "serverAuth"           },
                { KeyPurposeID.id_kp_smartcardlogon,       "smartcardLogon"       },
                { KeyPurposeID.id_kp_timeStamping,         "timeStamping"         },
                { MakeOid("1.3.6.1.4.1.311.10.12.1"),      "anyApplicationPolicy" },
                { MakeOid("1.3.6.1.4.1.311.10.3.1"),       "certTrustListSigning" },
                { MakeOid("1.3.6.1.4.1.311.10.3.11"),      "keyRecovery"          },
                { MakeOid("1.3.6.1.4.1.311.10.3.12"),      "documentSigning"      },
                { MakeOid("1.3.6.1.4.1.311.10.3.2"),       "timeStampSigning"     },
                { MakeOid("1.3.6.1.4.1.311.10.3.4"),       "encryptedFileSystem"  },
                { MakeOid("1.3.6.1.4.1.311.10.3.4.1"),     "efsRecovery"          },
                { MakeOid("1.3.6.1.4.1.311.10.3.5"),       "whqlCrypto"           },
                { MakeOid("1.3.6.1.4.1.311.10.3.7"),       "oemWHQLCrypto"        },
                { MakeOid("1.3.6.1.4.1.311.10.3.8"),       "embeddedNTCrypto"     },
                { MakeOid("1.3.6.1.4.1.311.10.3.9"),       "rootListSigner"       },
                { MakeOid("1.3.6.1.4.1.311.10.5.1"),       "drm"                  },
                { MakeOid("1.3.6.1.4.1.311.10.6.1"),       "licenses"             },
                { MakeOid("1.3.6.1.4.1.311.10.6.2"),       "licenseServer"        },
                { MakeOid("1.3.6.1.4.1.311.20.1"),         "autoEnrollCtlUsage"   },
                { MakeOid("1.3.6.1.4.1.311.20.2.1"),       "enrollmentAgent"      },
                { MakeOid("1.3.6.1.4.1.311.21.19"),        "dsEmailReplication"   },
                { MakeOid("1.3.6.1.4.1.311.21.5"),         "caExchange"           },
                { MakeOid("1.3.6.1.5.5.8.2.2"),            "ikeIntermediate"      }
            };
            return new ReadOnlyDictionary<DerObjectIdentifier, string>(builder);
        }

        private static IDictionary<DerObjectIdentifier, string> CreateLookup_AuthInfoAccess()
        {
            Dictionary<DerObjectIdentifier, string> builder = new Dictionary<DerObjectIdentifier, string>
            {
                { X509ObjectIdentifiers.IdADOcsp,      "ocsp"     },
                { X509ObjectIdentifiers.IdADCAIssuers, "caIssuer" }
            };
            return new ReadOnlyDictionary<DerObjectIdentifier, string>(builder);
        }

        private static IDictionary<ECCurve, string> CreateLookup_EccCurveNames()
        {
            Dictionary<ECCurve, string> builder = new Dictionary<ECCurve, string>();
            foreach (KeyValuePair<ECCurve, string> entry in ECNamedCurveTable.Names
                .Select(name => new KeyValuePair<ECCurve, string>(ECNamedCurveTable.GetByName(name).Curve, name)))
            {
                AddIfNotExists(builder, entry.Key, entry.Value);
            }
            foreach (KeyValuePair<ECCurve, string> entry in CustomNamedCurves.Names
                .Select(name => new KeyValuePair<ECCurve, string>(CustomNamedCurves.GetByName(name).Curve, name)))
            {
                AddIfNotExists(builder, entry.Key, entry.Value);
            }
            return new ReadOnlyDictionary<ECCurve, string>(builder);
        }

        private static string ParseKeyUsage(bool[] keyUsageFlags)
        {
            if (IsNotNull(keyUsageFlags))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (string keyUsage in keyUsageFlags.Select((value, index) => value ? (int?)index : null)
                        .Where(item => item.HasValue).Select(item => DecodeKeyUsage(item.Value)))
                    {
                        Append(sb, keyUsage);
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string DecodeKeyUsage(int index)
        {
            switch (index)
            {
                case 0: return "digitalSignature";
                case 1: return "nonRepudiation";
                case 2: return "keyEncipherment";
                case 3: return "dataEncipherment";
                case 4: return "keyAgreement";
                case 5: return "keyCertSign";
                case 6: return "cRLSign";
                case 7: return "encipherOnly";
                case 8: return "decipherOnly";
            }
            return $"#{index}";
        }

        private static string ParseExtendedKeyUsage(IList<DerObjectIdentifier> extendedKeyUsage)
        {
            if (IsNotNull(extendedKeyUsage))
            {
                try
                {
                    IDictionary<DerObjectIdentifier, string> lookup = EXT_KEY_USAGE.Value;
                    StringBuilder sb = new StringBuilder();
                    foreach (string extKeyUsage in extendedKeyUsage.Select(oid => GetValueOrDefault(lookup, oid, oid.Id)))
                    {
                        Append(sb, extKeyUsage);
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string ParseSubjectAlternativeNames(IList<IList<object>> subjectAlternativeNames)
        {
            if (IsNotNull(subjectAlternativeNames))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    object value;
                    foreach (IList<object> name in subjectAlternativeNames.Where(item => item.Count >= 2))
                    {
                        if (IsNotNull(value = name[1]))
                        {
                            Append(sb, EscapeString(DecodeGeneralNameValue(value)));
                        }
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string ParsePublicKey(AsymmetricKeyParameter asymmetricKeyParameter)
        {
            if (IsNotNull(asymmetricKeyParameter))
            {
                try
                {
                    if (asymmetricKeyParameter is ElGamalKeyParameters egKey)
                    {
                        ElGamalParameters param = egKey.Parameters;
                        return $"ElGamal, key size: {((param.L != 0) ? param.L : param.P.BitLength)} bits";
                    }
                    else if (asymmetricKeyParameter is DsaPublicKeyParameters dsaKey)
                    {
                        return $"DSA, key size: {dsaKey.Parameters.P.BitLength} bits";
                    }
                    else if (asymmetricKeyParameter is RsaKeyParameters rsaKey)
                    {
                        return $"RSA, key size: {rsaKey.Modulus.BitLength} bits, public exponent: 0x{ToHexString(rsaKey.Exponent)}";
                    }
                    else if (asymmetricKeyParameter is ECPublicKeyParameters eccKey)
                    {
                        string curveName = GetValueOrDefault(ECC_CURVE_NAMES.Value, eccKey.Parameters.Curve, "unknown");
                        return $"ECC, key size: {eccKey.Parameters.N.BitLength} bits, curve: {curveName}";
                    }
                    else
                    {
                        return $"Other ({asymmetricKeyParameter.GetType().Name})";
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private string ParseSignatureInfo(string sigAlgName, DerBitString signature)
        {
            if (IsNotEmpty(sigAlgName) && IsNotNull(signature))
            {
                try
                {
                    return $"{sigAlgName}, length: {(signature.GetBitStream().Length * 8) - signature.PadBits} bits";
                }
                catch { }
            }
            return sigAlgName;
        }

        private static string ParseSubjectKeyIdentifier(SubjectKeyIdentifier subjectKeyId)
        {
            if (IsNotNull(subjectKeyId))
            {
                return ToHexString(subjectKeyId.GetKeyIdentifier());
            }
            return string.Empty;
        }

        private static string ParseAuthorityKeyIdentifier(AuthorityKeyIdentifier authorityKeyId)
        {
            if (IsNotNull(authorityKeyId))
            {
                return ToHexString(authorityKeyId.GetKeyIdentifier());
            }
            return string.Empty;
        }

        private static string ParseCrlDistributionPoints(CrlDistPoint crlDistPoints)
        {
            if (IsNotNull(crlDistPoints))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (GeneralName name in crlDistPoints.GetDistributionPoints()
                        .Select(point => point.DistributionPointName)
                        .Where(name => IsNotNull(name) && (name.Type == 0)).Select(name => name.Name)
                        .OfType<GeneralNames>().SelectMany(names => names.GetNames()))
                    {
                        Append(sb, EscapeString(DecodeGeneralNameValue(name.Name)));
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }

            }
            return string.Empty;
        }

        private static string ParseAuthorityInformationAccess(AuthorityInformationAccess authorityInformationAccess)
        {
            if (IsNotNull(authorityInformationAccess))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    GeneralName location;
                    DerObjectIdentifier method;
                    foreach (AccessDescription descr in authorityInformationAccess.GetAccessDescriptions())
                    {
                        if (IsNotNull(location = descr.AccessLocation))
                        {
                            method = descr.AccessMethod;
                            if (X509ObjectIdentifiers.IdADCAIssuers.Equals(method))
                            {
                                Append(sb, EscapeString(DecodeGeneralNameValue(location.Name)));
                            }
                            else if (X509ObjectIdentifiers.IdADOcsp.Equals(method))
                            {
                                Append(sb, EscapeString(DecodeGeneralNameValue(location.Name)));
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
            return string.Empty;
        }

        private static string ParseCertificatePolicies(CertificatePolicies certificatePolicies)
        {
            if (IsNotNull(certificatePolicies))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (PolicyInformation policyInfo in certificatePolicies.GetPolicyInformation())
                    {
                        Append(sb, policyInfo.PolicyIdentifier.Id);
                    }
                    if (sb.Length > 0)
                    {
                        return sb.ToString();
                    }
                }
                catch { }

            }
            return string.Empty;
        }

        private static string DecodeGeneralNameType(int? type)
        {
            if (type.HasValue)
            {
                switch (type.Value)
                {
                    case GeneralName.OtherName:                 return "otherName";
                    case GeneralName.Rfc822Name:                return "rfc822Name";
                    case GeneralName.DnsName:                   return "dNSName";
                    case GeneralName.X400Address:               return "x400Address";
                    case GeneralName.DirectoryName:             return "directoryName";
                    case GeneralName.EdiPartyName:              return "ediPartyName";
                    case GeneralName.UniformResourceIdentifier: return "uri";
                    case GeneralName.IPAddress:                 return "iPAddress";
                    case GeneralName.RegisteredID:              return "registeredID";
                }
                return $"type#{type.Value}";
            }
            return string.Empty;
        }

        private static string DecodeGeneralNameValue(object value)
        {
            if (value is string)
            {
                return (string)value;
            }
            else if (value is Asn1Encodable)
            {
                return DecodeGeneralNameValue((Asn1Encodable)value);
            }
            else
            {
                return string.Empty;
            }
        }

        private static string DecodeGeneralNameValue(Asn1Encodable value)
        {
            if (value is DerStringBase str)
            {
                return str.GetString();
            }
            else if (value is DerObjectIdentifier id)
            {
                return id.Id;
            }
            else if (value is DerOctetString bytes)
            {
                return ToHexString(bytes.GetOctets());
            }
            else if (value is GeneralName name)
            {
                return DecodeGeneralNameValue(name.Name);
            }
            else if (IsNotNull(value))
            {
                return $"{value.GetType().Name}={value}";
            }
            else
            {
                return string.Empty;
            }
        }

        private static IEnumerable<Tuple<string, string>> DecodePolicyInformation(PolicyInformation policyInformation)
        {
            if (IsNotNull(policyInformation))
            {
                yield return Tuple.Create("oid", policyInformation.PolicyIdentifier.Id);
                Asn1Sequence qualifiers;
                if (IsNotNull(qualifiers = policyInformation.PolicyQualifiers))
                {
                    foreach (Asn1Sequence qualifier in qualifiers.OfType<Asn1Sequence>().Where(sequence => sequence.Count >= 2))
                    {
                        if ((qualifier[0] is DerObjectIdentifier id) && PolicyQualifierID.IdQtCps.Equals(id) && (qualifier[1] is DerStringBase value))
                        {
                            yield return Tuple.Create("cps", value.GetString());
                        }
                    }
                }
            }
        }

        private static SubjectKeyIdentifier GetSubjectKeyIdentifier(X509Certificate cert)
        {
            if (IsNotNull(cert))
            {
                try
                {
                    Asn1Object data;
                    if (IsNotNull(data = X509ExtensionUtilities.FromExtensionValue(cert, X509Extensions.SubjectKeyIdentifier)))
                    {
                        return SubjectKeyIdentifier.GetInstance(data);
                    }
                }
                catch { }
            }
            return null;
        }

        private static AuthorityKeyIdentifier GetAuthorityKeyIdentifier(X509Certificate cert)
        {
            if (IsNotNull(cert))
            {
                try
                {
                    Asn1Object data;
                    if (IsNotNull(data = X509ExtensionUtilities.FromExtensionValue(cert, X509Extensions.AuthorityKeyIdentifier)))
                    {
                        return AuthorityKeyIdentifier.GetInstance(data);
                    }
                }
                catch { }
            }
            return null;
        }

        private static CrlDistPoint GetCrlDistributionPoints(X509Certificate cert)
        {
            if (IsNotNull(cert))
            {
                try
                {
                    Asn1Object data;
                    if (IsNotNull(data = X509ExtensionUtilities.FromExtensionValue(cert, X509Extensions.CrlDistributionPoints)))
                    {
                        return CrlDistPoint.GetInstance(data);
                    }
                }
                catch { }
            }
            return null;
        }

        private static AuthorityInformationAccess GetAuthorityInformationAccess(X509Certificate cert)
        {
            if (IsNotNull(cert))
            {
                try
                {
                    Asn1Object data;
                    if (IsNotNull(data = X509ExtensionUtilities.FromExtensionValue(cert, X509Extensions.AuthorityInfoAccess)))
                    {
                        return AuthorityInformationAccess.GetInstance(data);
                    }
                }
                catch { }
            }
            return null;
        }

        private static CertificatePolicies GetCertificatePolicies(X509Certificate cert)
        {
            if (IsNotNull(cert))
            {
                try
                {
                    Asn1Object data;
                    if (IsNotNull(data = X509ExtensionUtilities.FromExtensionValue(cert, X509Extensions.CertificatePolicies)))
                    {
                        return CertificatePolicies.GetInstance(data);
                    }
                }
                catch { }
            }
            return null;
        }

        private static string X500NameToRFC2253(X509Name name, bool reverse)
        {
            if (IsNotNull(name))
            {
                try
                {
                    string value;
                    if (IsNotEmpty(value = name.ToString(reverse, X509_NAME_ATTRIBUTES.Value)))
                    {
                        return value;
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string CreatePemData(string name, Asn1Encodable ans1object)
        {
            if (IsNotEmpty(name) && IsNotNull(ans1object))
            {
                try
                {
                    using (StringWriter textWriter = new StringWriter())
                    {
                        PemWriter pemWriter = new PemWriter(textWriter);
                        pemWriter.WriteObject(new PemObject(name, ans1object.GetDerEncoded()));
                        textWriter.Flush();
                        return textWriter.ToString();
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string CreateAsn1Dump(Asn1Encodable ans1object)
        {
            if (IsNotNull(ans1object))
            {
                try
                {
                    return Asn1Dump.DumpAsString(ans1object, true);
                }
                catch (Exception e)
                {
                    return e.ToString();
                }
            }
            return string.Empty;
        }

        private string DecodePathLenConstraint(int constraint)
        {
            if (constraint < 0)
            {
                throw new ArgumentOutOfRangeException("Constraint must be a non-negative value!");
            }
            return (constraint == int.MaxValue) ? "unrestricted" : constraint.ToString();
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
        private static DerObjectIdentifier MakeOid(string id)
        {
            return new DerObjectIdentifier(id);
        }
    }
}
