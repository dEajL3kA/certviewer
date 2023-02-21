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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using System.Windows;

using Microsoft.Win32;

using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

using CertViewer.Dialogs;

namespace CertViewer
{
    public enum DigestAlgo { MD5, RIPEMD160, SHA1, BLAKE2_160, BLAKE2_256, SHA224, SHA256, SHA3_224, SHA3_256 }

    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const int MAX_LENGTH = 128 * 1024 * 1024;
        private const int WM_DRAWCLIPBOARD = 0x0308;
        private const int WM_CHANGECBCHAIN = 0x030D;
        private const string BASE_TITLE = "Certificate Viewer";
        private const string UNSPECIFIED = "(Unspecified)";

        private static readonly Lazy<Tuple<Version, Version, DateTime>> PROGRAM_VERSION_INFORMATION = new Lazy<Tuple<Version, Version, DateTime>>(GetVersionAndBuildDate);
        private static readonly Lazy<IDictionary<DerObjectIdentifier, string>> X509_NAME_ATTRIBUTES = new Lazy<IDictionary<DerObjectIdentifier, string>>(CreateLookup_NameAttributes);
        private static readonly Lazy<IDictionary<DerObjectIdentifier, string>> EXT_KEY_USAGE = new Lazy<IDictionary<DerObjectIdentifier, string>>(CreateLookup_ExtKeyUsage);
        private static readonly Lazy<IDictionary<ECCurve, string>> ECC_CURVE_NAMES = new Lazy<IDictionary<ECCurve, string>>(CreateLookup_EccCurveNames);

        private static readonly Lazy<Regex> PEM_CERTIFICATE = new Lazy<Regex>(() => new Regex(@"-{3,}\s*BEGIN\s+CERTIFICATE\s*-{3,}(.+)-{3,}\s*END\s+CERTIFICATE\s*-{3,}", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled));
        private static readonly Lazy<Regex> INVALID_BASE64_CHARS = new Lazy<Regex>(() => new Regex(@"[^A-Za-z0-9+/]+", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled));
        private static readonly Lazy<Regex> CONTROL_CHARACTERS = new Lazy<Regex>(() => new Regex(@"[\u0000-\u001F\u007F]", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled));

        private bool m_initialized = false;
        private IntPtr? m_hWndSelf = null, m_hWndNext = null;

        public X509Certificate Certificate { get; private set; } = null;
        public DigestAlgo DigestAlgorithm { get; private set; } = DigestAlgo.SHA256;
        public bool EnableMonitorClipboard { get; private set; } = true;

        private readonly IDictionary<TabItem, int> m_tabs;
        private readonly ISet<TabItem> m_tabInitialized = new HashSet<TabItem>();

        // ==================================================================
        // Constructor
        // ==================================================================

        public MainWindow()
        {
            InitializeComponent();
            m_tabs = ItemsToDictionary<TabItem>(TabControl.Items);
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
                m_hWndNext = SetClipboardViewer((m_hWndSelf = source.Handle).Value);
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
            if (m_hWndSelf.HasValue && m_hWndNext.HasValue)
            {
                ChangeClipboardChain(m_hWndSelf.Value, m_hWndNext.Value);
            }
        }

        private void Window_PreviewDragEnter(object sender, DragEventArgs e)
        {
            try
            {
                e.Effects = ((OwnedWindows.Count == 0) && e.Data.GetDataPresent(DataFormats.FileDrop)) ? DragDropEffects.Copy : DragDropEffects.None;
                e.Handled = true;
            }
            catch { }
        }

        private void Window_PreviewDragLeave(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }

        private void Window_PreviewDrop(object sender, DragEventArgs e)
        {
            if (OwnedWindows.Count == 0)
            {
                try
                {
                    string[] droppedFiles = e.Data.GetData(DataFormats.FileDrop) as string[];
                    if (IsNotNull(droppedFiles))
                    {
                        foreach (string currentFile in droppedFiles)
                        {
                            try
                            {
                                if (ParseCertificateFile(currentFile))
                                {
                                    e.Handled = true;
                                    return;
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
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
                case WM_DRAWCLIPBOARD:
                    if (m_initialized && EnableMonitorClipboard)
                    {
                        ParseCertificateFromClipboard();
                    }
                    if (m_hWndNext.HasValue)
                    {
                        SendMessage(m_hWndNext.Value, msg, wParam, lParam);
                    }
                    handled = true;
                    break;
                case WM_CHANGECBCHAIN:
                    if (m_hWndNext.HasValue)
                    {
                        if (wParam == m_hWndNext.Value)
                        {
                            m_hWndNext = lParam;
                        }
                        else
                        {
                            SendMessage(m_hWndNext.Value, msg, wParam, lParam);
                        }
                    }
                    break;
            }
            return IntPtr.Zero;
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
                    TryCopyToClipboard(cert.SerialNumber.ToString(16).ToUpperInvariant());
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
                    TryCopyToClipboard((basicConstraints < 0) ? "End entity certificate" : $"CA certificate, {DecodePathLenConstraint(basicConstraints)}");
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
                try
                {
                    TryCopyToClipboard(ParsePublicKey(cert.GetPublicKey()));
                    SystemSounds.Beep.Play();
                }
                catch { }
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
                try
                {
                    TryCopyToClipboard(cert.SigAlgName);
                    SystemSounds.Beep.Play();
                }
                catch { }
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

        private void Button_AuthorityInformation_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowAuthorityInformationDetails(GetAuthorityInformationAccess(cert));
            }
        }

        private void Button_OcspServer_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate cert;
            if (IsNotNull(cert = Certificate))
            {
                ShowAuthorityInformationDetails(GetAuthorityInformationAccess(cert), true);
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
                    string digestHex = Hex.ToHexString(CalculateDigest(cert)).ToUpperInvariant();
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
            Certificate = null;
            TextBox_Asn1Data.Text = TextBox_BasicConstraints.Text = TextBox_Fingerprint.Text = 
                TextBox_ExtKeyUsage.Text = TextBox_Issuer.Text = TextBox_KeyUsage.Text = TextBox_NotAfter.Text =
                TextBox_NotBefore.Text = TextBox_PemData.Text = TextBox_PublicKey.Text = TextBox_Serial.Text =
                TextBox_SignAlgo.Text = TextBox_SubjAltNames.Text = TextBox_Subject.Text =
                TextBox_AuthorityKeyId.Text = TextBox_SubjectKeyId.Text = TextBox_CrlDistPoint.Text =
                TextBox_OcspServer.Text = TextBox_AuthorityInformation.Text = string.Empty;
            Image_NotBefore_Valid.Visibility = Image_NotBefore_Expired.Visibility = Image_NotAfter_Valid.Visibility = Image_NotAfter_Expired.Visibility = Visibility.Hidden;
            ShowPlaceholder(true);
            Tab_Extensions.IsEnabled = Tab_Asn1Data.IsEnabled = Tab_PemData.IsEnabled = false;
            TabControl.SelectedItem = Tab_CertInfo;
        }

        private void Label_Placeholder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            FrameworkElement element = sender as FrameworkElement;
            if (IsNotNull(element) && (element.Visibility == Visibility.Visible))
            {
                element.Visibility = Visibility.Hidden;
            }
        }

        private void Image_Placeholder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount == 2))
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.Filter = "Certificate Files|*.pem;*.der;*.cer;*.crt|All Files|*.*";
                if (openFileDialog.ShowDialog().GetValueOrDefault(false))
                {
                    ParseCertificateFile(openFileDialog.FileName);
                }
            }
        }

        private void Image_About_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount > 0))
            {
                Tuple<Version, Version, DateTime> version = PROGRAM_VERSION_INFORMATION.Value;
                StringBuilder sb = new StringBuilder();
                sb.AppendLine($"CertViewer v{version.Item1}, built on {version.Item3.ToString("yyyy-MM-dd")}");
                sb.AppendLine("Copyright (c) 2023 \"dEajL3kA\" <Cumpoing79@web.de>");
                sb.AppendLine("Released under the MIT license");
                sb.AppendLine("Website: https://github.com/dEajL3kA/certviewer");
                sb.AppendLine();
                sb.AppendLine($"Bouncy Castle Cryptography Library v{version.Item2}");
                sb.AppendLine("Copyright (c) 2000-2023 The Legion of the Bouncy Castle");
                sb.AppendLine("Released under the MIT license");
                sb.AppendLine("Website: https://github.com/bcgit/bc-csharp");
                sb.AppendLine();
                sb.AppendLine("No system of mass surveillance has existed in any society that we know of to this point that has not been abused!");
                MessageBox.Show(sb.ToString(), "About...", MessageBoxButton.OK, MessageBoxImage.Information);
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
                string[] commandLineArgs = Environment.GetCommandLineArgs();
                bool flag = false;
                foreach (string filename in commandLineArgs.Skip(1))
                {
                    if ((!flag) && filename.StartsWith("--", StringComparison.Ordinal))
                    {
                        if (filename.Equals("--", StringComparison.Ordinal))
                        {
                            flag = true;
                        }
                        continue;
                    }
                    if (ParseCertificateFile(filename))
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private void ParseCertificateFromClipboard()
        {
            using (OverrideCursor busy = new OverrideCursor())
            {
                HideErrorText();
                try
                {
                    string text;
                    if (IsNotEmpty(text = TryPasteFromClipboard()))
                    {
                        Match match = PEM_CERTIFICATE.Value.Match(text);
                        if (match.Success)
                        {
                            Title = $"Clipboard \u2013 {BASE_TITLE}";
                            ParseCertificateData(match.Groups[1].Value);
                        }
                    }
                }
                catch (Exception e)
                {
                    TabControl.SelectedItem = Tab_CertInfo;
                    Certificate = null;
                    ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}");
                }
            }
        }

        private bool ParseCertificateFile(string fileName)
        {
            using (OverrideCursor busy = new OverrideCursor())
            {
                HideErrorText();
                try
                {
                    byte[] data = ReadFileContents(fileName, MAX_LENGTH);
                    if (IsNotEmpty(data))
                    {
                        Title = $"{GetBaseName(fileName)} \u2013 {BASE_TITLE}";
                        Match match = PEM_CERTIFICATE.Value.Match(Encoding.UTF8.GetString(data));
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
                }
                catch (Exception e)
                {
                    TabControl.SelectedItem = Tab_CertInfo;
                    Certificate = null;
                    ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}");
                }
            }
            return false;
        }

        private void ParseCertificateData(string pemText)
        {
            try
            {
                ParseCertificateData(Convert.FromBase64String(AddPadding(INVALID_BASE64_CHARS.Value.Replace(pemText, string.Empty))));
            }
            catch (Exception e)
            {
                TabControl.SelectedItem = Tab_CertInfo;
                Certificate = null;
                ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}");
            }
        }

        private void ParseCertificateData(byte[] data)
        {
            try
            {
                X509Certificate cert = new X509CertificateParser().ReadCertificate(data);
                m_tabInitialized.Clear();
                if (IsNotNull(Certificate = cert))
                {
                    string subjectDN = X500NameToRFC2253(cert.SubjectDN);
                    SetText(TextBox_Subject, DefaultString(subjectDN, UNSPECIFIED));
                    Button_SubjectDN.IsEnabled = IsNotEmpty(subjectDN);
                    string issuerDN = X500NameToRFC2253(cert.IssuerDN);
                    SetText(TextBox_Issuer, DefaultString(issuerDN, UNSPECIFIED));
                    Button_IssuerDN.IsEnabled = IsNotEmpty(issuerDN);
                    SetText(TextBox_Serial, $"0x{cert.SerialNumber.ToString(16).ToUpperInvariant()}");
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
                    SetText(TextBox_PublicKey, ParsePublicKey(cert.GetPublicKey()));
                    SetText(TextBox_SignAlgo, cert.SigAlgName);
                    SetText(TextBox_Fingerprint, Hex.ToHexString(CalculateDigest(cert)).ToUpperInvariant());
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
                ShowPlaceholder(true, $"{e.GetType().Name}: {e.Message}");
            }
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
                            Tuple<string, string> authorityInformationAccess = ParseAuthorityInformationAccess(GetAuthorityInformationAccess(cert));
                            SetText(TextBox_AuthorityInformation, DefaultString(authorityInformationAccess.Item1, UNSPECIFIED));
                            Button_AuthorityInformation.IsEnabled = IsNotEmpty(authorityInformationAccess.Item1);
                            SetText(TextBox_OcspServer, DefaultString(authorityInformationAccess.Item2, UNSPECIFIED));
                            Button_OcspServer.IsEnabled = IsNotEmpty(authorityInformationAccess.Item2);
                            break;
                        case 2:
                            SetText(TextBox_Asn1Data, CreateAsn1Dump(cert.CertificateStructure));
                            break;
                        case 3:
                            SetText(TextBox_PemData, CreatePemData(cert.GetEncoded()));
                            break;
                    }
                }
                catch { }
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
                                .Zip(valList, (key, value) => new KeyValuePair<string, string>(key, EscapeString(value, false)));
                        if (items.Any())
                        {
                            DetailsView viewer = new DetailsView(items.Reverse()) { Owner = this, Title = title };
                            viewer.ShowDialog(busy);
                        }
                    }
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
                        .Select(item => new KeyValuePair<string, string>(DecodeGeneralNameType(item[0] as int?), EscapeString(item[1] as string, false)))
                        .Where(item => IsNotEmpty(item.Key) && IsNotEmpty(item.Value));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = "Subject Alternative Names" };
                        viewer.ShowDialog(busy);
                    }
                }
            }
        }
        
        private void ShowAuthorityInformationDetails(AuthorityInformationAccess authorityInformationAccess, bool showOcsp = false)
        {
            if (IsNotNull(authorityInformationAccess))
            {
                using (OverrideCursor busy = new OverrideCursor())
                {
                    DerObjectIdentifier identifier = showOcsp ? X509ObjectIdentifiers.IdADOcsp : X509ObjectIdentifiers.IdADCAIssuers;
                    IEnumerable<KeyValuePair<string, string>> items = authorityInformationAccess.GetAccessDescriptions()
                        .Where(descr => identifier.Equals(descr.AccessMethod))
                        .Select(descr => descr.AccessLocation)
                        .Where(IsNotNull)
                        .Select(name => new KeyValuePair<string, string>(DecodeGeneralNameType(name.TagNo), EscapeString(DecodeGeneralNameValue(name.Name), false)))
                        .Where(item => IsNotEmpty(item.Key) && IsNotEmpty(item.Value));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = showOcsp ? "OCSP Server" : "Authority Information Access" };
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
                        .SelectMany(names => names.GetNames())
                        .Select(name => new KeyValuePair<string, string>(DecodeGeneralNameType(name.TagNo), EscapeString(DecodeGeneralNameValue(name.Name), false)))
                        .Where(item => IsNotEmpty(item.Key) && IsNotEmpty(item.Value));
                    if (items.Any())
                    {
                        DetailsView viewer = new DetailsView(items) { Owner = this, Title = "CRL Distribution Points" };
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
                        case DigestAlgo.MD5:
                            return DigestUtilities.CalculateDigest("MD5", cert.GetEncoded());
                        case DigestAlgo.RIPEMD160:
                            return DigestUtilities.CalculateDigest("RIPEMD-160", cert.GetEncoded());
                        case DigestAlgo.SHA1:
                            return DigestUtilities.CalculateDigest("SHA-1", cert.GetEncoded());
                        case DigestAlgo.SHA224:
                            return DigestUtilities.CalculateDigest("SHA-224", cert.GetEncoded());
                        case DigestAlgo.SHA256:
                            return DigestUtilities.CalculateDigest("SHA-256", cert.GetEncoded());
                        case DigestAlgo.SHA3_224:
                            return DigestUtilities.CalculateDigest("SHA3-224", cert.GetEncoded());
                        case DigestAlgo.SHA3_256:
                            return DigestUtilities.CalculateDigest("SHA3-256", cert.GetEncoded());
                        case DigestAlgo.BLAKE2_160:
                            return DigestUtilities.CalculateDigest("BLAKE2B-160", cert.GetEncoded());
                        case DigestAlgo.BLAKE2_256:
                            return DigestUtilities.CalculateDigest("BLAKE2B-256", cert.GetEncoded());
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
                SetText(TextBox_Fingerprint, Hex.ToHexString(CalculateDigest(cert)).ToUpperInvariant());
            }
        }

        private void ShowPlaceholder(bool show, string placeholderText = null)
        {
            Tab_Extensions.IsEnabled = Tab_PemData.IsEnabled = Tab_Asn1Data.IsEnabled = show ? false : true;
            Panel_Placeholder.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            Panel_CertInfo.Visibility = show ? Visibility.Hidden : Visibility.Visible;
            Label_Placeholder.Visibility = IsNotEmpty(placeholderText) ? Visibility.Visible : Visibility.Hidden;
            Label_Placeholder.Content = IsNotEmpty(placeholderText) ? placeholderText : string.Empty;
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
            if (Label_Placeholder.Visibility == Visibility.Visible)
            {
                Label_Placeholder.Visibility = Visibility.Hidden;
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
            try
            {
                if (asymmetricKeyParameter is RsaKeyParameters)
                {
                    RsaKeyParameters rsaKey = (RsaKeyParameters) asymmetricKeyParameter;
                    return $"RSA, key size: {rsaKey.Modulus.BitLength}, public exponent: 0x{rsaKey.Exponent:X}";
                }
                else if (asymmetricKeyParameter is ECKeyParameters)
                {
                    ECKeyParameters ecKey = (ECKeyParameters)asymmetricKeyParameter;
                    string curveName = GetValueOrDefault(ECC_CURVE_NAMES.Value, ecKey.Parameters.Curve, "Unknown");
                    return $"ECC, key size: {ecKey.Parameters.N.BitLength}, curve: {curveName}";
                }
                else
                {
                    return asymmetricKeyParameter.GetType().Name;
                }
            }
            catch { }
            return string.Empty;
        }

        private static string ParseSubjectKeyIdentifier(SubjectKeyIdentifier subjectKeyId)
        {
            if (IsNotNull(subjectKeyId))
            {
                return Hex.ToHexString(subjectKeyId.GetKeyIdentifier()).ToUpperInvariant();
            }
            return string.Empty;
        }

        private static string ParseAuthorityKeyIdentifier(AuthorityKeyIdentifier authorityKeyId)
        {
            if (IsNotNull(authorityKeyId))
            {
                return Hex.ToHexString(authorityKeyId.GetKeyIdentifier()).ToUpperInvariant();
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

        private static Tuple<string, string> ParseAuthorityInformationAccess(AuthorityInformationAccess authorityInformationAccess)
        {
            if (IsNotNull(authorityInformationAccess))
            {
                try
                {
                    StringBuilder sbCaIssuer = new StringBuilder(), sbOcsp = new StringBuilder();
                    GeneralName location;
                    DerObjectIdentifier method;
                    foreach (AccessDescription descr in authorityInformationAccess.GetAccessDescriptions())
                    {
                        if (IsNotNull(location = descr.AccessLocation))
                        {
                            method = descr.AccessMethod;
                            if (X509ObjectIdentifiers.IdADCAIssuers.Equals(method))
                            {
                                Append(sbCaIssuer, EscapeString(DecodeGeneralNameValue(location.Name)));
                            }
                            else if (X509ObjectIdentifiers.IdADOcsp.Equals(method))
                            {
                                Append(sbOcsp, EscapeString(DecodeGeneralNameValue(location.Name)));
                            }
                        }
                    }
                    if ((sbCaIssuer.Length > 0) || (sbOcsp.Length > 0))
                    {
                        return Tuple.Create(sbCaIssuer.ToString(), sbOcsp.ToString());
                    }
                }
                catch { }

            }
            return Tuple.Create(string.Empty, string.Empty);
        }

        private static string DecodeGeneralNameType(int? type)
        {
            if (type.HasValue)
            {
                switch (type.Value)
                {
                    case 0: return "otherName";
                    case 1: return "rfc822Name";
                    case 2: return "dNSName";
                    case 3: return "x400Address";
                    case 4: return "directoryName";
                    case 5: return "ediPartyName";
                    case 6: return "uniformResourceIdentifier";
                    case 7: return "iPAddress";
                    case 8: return "registeredID";
                }
                return $"#{type.Value}";
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
            if (value is DerStringBase)
            {
                return ((DerStringBase)value).GetString();
            }
            else if (value is DerOctetString)
            {
                return Hex.ToHexString(((DerOctetString)value).GetOctets()).ToUpperInvariant();
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

        private static string X500NameToRFC2253(X509Name name)
        {
            if (IsNotNull(name))
            {
                try
                {
                    string value;
                    if (IsNotEmpty(value = name.ToString(true, X509_NAME_ATTRIBUTES.Value)))
                    {
                        return value;
                    }
                }
                catch { }
            }
            return string.Empty;
        }

        private static string CreatePemData(byte[] content)
        {
            if (IsNotEmpty(content))
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
            if (IsNotNull(data))
            {
                try
                {
                    return Asn1Dump.DumpAsString(data);
                }
                catch { }
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

        private static void Append(StringBuilder sb, string text)
        {
            if ((text = TrimToEmpty(text)).Length > 0)
            {
                if (sb.Length > 0)
                {
                    sb.Append(", ");
                }
                sb.Append(text.Trim());
            }
        }

        private static void SetText(TextBox textBox, string text)
        {
            if (IsNotNull(textBox))
            {
                int maxLength = textBox.MaxLength;
                maxLength = (maxLength > 0) ? Math.Max(maxLength, 4) : int.MaxValue;
                text = IsNotEmpty(text) ? text.Trim() : string.Empty;
                textBox.Text = (text.Length > maxLength) ? $"{text.Substring(0, maxLength - 3)}..." : text;
            }
        }

        private static void BringWindowToFront(IntPtr? hwnd)
        {
            if (hwnd.HasValue)
            {
                SetForegroundWindow(hwnd.Value);
            }
        }

        private static Tuple<Version, Version, DateTime> GetVersionAndBuildDate()
        {
            try
            {
                Assembly executingAssembly = Assembly.GetExecutingAssembly();
                AssemblyInformationalVersionAttribute appVersion = GetInformationalVersion(executingAssembly);
                AssemblyInformationalVersionAttribute bcVersion = GetInformationalVersion(Assembly.GetAssembly(typeof(X509Certificate)));
                return Tuple.Create(TryParseVersion(appVersion),
                    TryParseVersion(bcVersion),
                    TryParseBuildDate(executingAssembly.GetName().Version));
            }
            catch { }
            return Tuple.Create(new Version(0, 0), new Version(0, 0), new DateTime(1970, 1, 1));
        }

        private static Version TryParseVersion(AssemblyInformationalVersionAttribute attrib)
        {
            if (IsNotNull(attrib))
            {
                Version version;
                if (Version.TryParse(attrib.InformationalVersion.Split('+').First(), out version))
                {
                    return version;
                }
            }
            return new Version();
        }

        private static AssemblyInformationalVersionAttribute GetInformationalVersion(Assembly assembly)
        {
            if (IsNotNull(assembly))
            {
                return Attribute.GetCustomAttribute(assembly, typeof(AssemblyInformationalVersionAttribute), false) as AssemblyInformationalVersionAttribute;
            }
            return new AssemblyInformationalVersionAttribute(string.Empty);
        }
        
        private static DateTime TryParseBuildDate(Version version)
        {
            DateTime dateOffset = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            if (IsNotNull(version))
            {
                return dateOffset.Add(new TimeSpan(TimeSpan.TicksPerDay * version.Build + TimeSpan.TicksPerSecond * 2 * version.Revision));
            }
            return dateOffset;
        }

        private static string DefaultString(string text, string defaultString)
        {
            return IsNotEmpty(text) ? text : defaultString;
        }

        private static string EscapeString(string str, bool escapeComma = true)
        {
            if (IsNotEmpty(str))
            {
                str = str.Replace("\\", "\\\\");
                if (escapeComma)
                {
                    str = str.Replace(",", "\\,");
                }
                str = str.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
                return CONTROL_CHARACTERS.Value.Replace(str, string.Empty);
            }
            return str;
        }

        private static byte[] ReadFileContents(string filePath, int maxLength)
        {
            byte[] buffer = Array.Empty<byte>();
            try
            {
                using (FileStream stream = TryOpenFile(filePath, FileMode.Open, FileAccess.Read))
                {
                    int length = (int) Math.Min(stream.Length, maxLength);
                    if (length > 0)
                    {
                        buffer = new byte[length];
                        int count, offset = 0;
                        while (offset < length)
                        {
                            if ((count = stream.Read(buffer, offset, length - offset)) < 1)
                            {
                                return CopySubArray(buffer, offset);
                            }
                            offset += count;
                        }
                    }
                }
            }
            catch { }
            return buffer;
        }

        private static FileStream TryOpenFile(string filePath, FileMode mode, FileAccess access)
        {
            for (int i = 1; i <= 32; ++i)
            {
                try
                {
                    return File.Open(filePath, mode, access);
                }
                catch { }
                Thread.Sleep(i);
            }
            return File.Open(filePath, mode, access);
        }

        private static string TryPasteFromClipboard()
        {
            for (int i = 1; i <= 16; ++i)
            {
                try
                {
                    return Clipboard.GetText();
                }
                catch { }
                Thread.Sleep(i);
            }
            return Clipboard.GetText();
        }

        private static void TryCopyToClipboard(string text)
        {
            if (IsNotEmpty(text))
            {
                for (int i = 1; i <= 16; ++i)
                {
                    try
                    {
                        Clipboard.SetText(text);
                        return;
                    }
                    catch { }
                    Thread.Sleep(i);
                }
                Clipboard.SetText(text);
            }
        }

        private object GetBaseName(string fileName)
        {
            if (IsNotEmpty(fileName))
            {
                try
                {
                    return Path.GetFileName(fileName);
                }
                catch { }
            }
            return string.Empty;
        }

        private static byte[] CopySubArray(byte[] buffer, int length)
        {
            byte[] newBuffer = Array.Empty<byte>();
            if (IsNotEmpty(buffer))
            {
                int newLength = Math.Min(length, buffer.Length);
                if (newLength > 0)
                {
                    newBuffer = new byte[newLength];
                    Array.Copy(buffer, newBuffer, newLength);
                }
            }
            return newBuffer;
        }

        private static void GetSettingsValue(KeyValueConfigurationCollection settings, string name, Action<string> handler)
        {
            try
            {
                KeyValueConfigurationElement element = settings[name];
                if (IsNotNull(element))
                {
                    string value;
                    if (IsNotEmpty(value = element.Value))
                    {
                        handler(value);
                    }

                }
            }
            catch { }
        }

        private static bool AddIfNotExists<TKey, TValue>(Dictionary<TKey, TValue> dictionary, TKey key, TValue value)
        {
            if (!dictionary.ContainsKey(key))
            {
                dictionary.Add(key, value);
                return true;
            }
            return false;
        }

        private static TValue GetValueOrDefault<TKey, TValue>(IDictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue)
        {
            if (IsNotNull(dictionary) && IsNotNull(key))
            {
                TValue value;
                if (dictionary.TryGetValue(key, out value))
                {
                    return value;
                }
            }
            return defaultValue;
        }

        private static DerObjectIdentifier MakeOid(string id)
        {
            return new DerObjectIdentifier(id);
        }

        private static IDictionary<T, int> ItemsToDictionary<T>(ItemCollection items)
        {
            int index = 0;
            return CollectionUtilities.ReadOnly(items.OfType<T>().ToDictionary(item => item, item => index++));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotNull(object value)
        {
            return !ReferenceEquals(value, null);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotEmpty(byte[] data)
        {
            return (!ReferenceEquals(data, null)) && (data.Length > 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotEmpty(string text)
        {
            return !string.IsNullOrEmpty(text);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotEmpty<T>(IList<T> list)
        {
            return (!ReferenceEquals(list, null)) && (list.Count > 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static string TrimToEmpty(string text)
        {
            return (!ReferenceEquals(text, null)) ? text.Trim() : string.Empty;
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

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool ChangeClipboardChain(IntPtr hWndRemove, IntPtr hWndNewViewer);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetForegroundWindow(IntPtr hWnd);
    }
}
