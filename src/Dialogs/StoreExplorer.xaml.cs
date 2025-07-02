/*
 * CertViewer - simple X.509 certificate viewer
 * Copyright (c) 2025 "dEajL3kA" <Cumpoing79@web.de>
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
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

using CertViewer.Utilities;
using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class StoreExplorer : WindowEx
    {
        private static volatile bool s_hideNotValidCerts = true;
        private static volatile StoreName s_selectedStoreName = StoreName.My;

        protected bool HideNotValidCerts { get; set; } = true;
        protected StoreName SelectedStoreName { get; set; } = StoreName.My;

        public StoreExplorer()
        {
            InitializeComponent();
            CheckBox_HideExpiredCerts.IsChecked = HideNotValidCerts = s_hideNotValidCerts;
            SelectedStoreName = s_selectedStoreName;
            foreach (StoreName storeName in Enum.GetValues(typeof(StoreName)))
            {
                ComboBox_StoreNames.Items.Add(storeName);
            }
            List_Certificates.Items.SortDescriptions.Add(new SortDescription("Subject", ListSortDirection.Ascending));
            List_Certificates.Items.SortDescriptions.Add(new SortDescription("Issuer", ListSortDirection.Ascending));
            List_Certificates.Items.SortDescriptions.Add(new SortDescription("SerialNumber", ListSortDirection.Ascending));
        }

        protected override void InitializeGui(IntPtr hWnd)
        {
            MinWidth = ActualWidth;
            MinHeight = ActualHeight;
            try
            {
                DisableMinimizeMaximizeButtons(hWnd);
                BringWindowToFront(hWnd);
            }
            catch { }
            Dispatcher.BeginInvoke(DispatcherPriority.Render, new Action(InitializeCertificateView));
            Keyboard.ClearFocus();
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (!(IsNotNull(Button_Cancel) && Button_Cancel.IsEnabled))
            {
                e.Cancel = true;
            }
        }

        public byte[] SelectedCertificate
        {
            get
            {
                if (IsNotNull(List_Certificates))
                {
                    if (List_Certificates.SelectedItem is X509Certificate2 cert)
                    {
                        return cert.RawData;
                    }
                }
                return null;
            }
        }

        private void InitializeCertificateView()
        {
            try
            {
                ComboBox_StoreNames.SelectedIndex = ComboBox_StoreNames.Items.IndexOf(SelectedStoreName);
            }
            catch { }
        }

        private void ComboBox_StoreNames_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialized && e.AddedItems.Count > 0)
            {
                if (e.AddedItems[0] is StoreName storeName)
                {
                    LoadCertificateList(SelectedStoreName = storeName, HideNotValidCerts);
                }
            }
            e.Handled = true;
        }

        private async void LoadCertificateList(StoreName storeName, bool excludeExpired)
        {
            Panel_Buttons.IsEnabled = false;
            List_Certificates.Items.Clear();
            Text_Placeholder.Visibility = Visibility.Collapsed;
            Text_Loading.Visibility = Visibility.Visible;
            try
            {
                await DoEvents(Dispatcher);
                using (OverrideCursor busy = new OverrideCursor(Cursors.Wait))
                {
                    using (X509Store store = new X509Store(storeName, StoreLocation.CurrentUser))
                    {
                        store.Open(OpenFlags.ReadOnly);
                        DateTime now = DateTime.UtcNow;
                        foreach (X509Certificate2 certificate in store.Certificates)
                        {
                            if ((!excludeExpired) || ((certificate.NotBefore.ToUniversalTime().CompareTo(now) <= 0) && (certificate.NotAfter.ToUniversalTime().CompareTo(now) >= 0)))
                            {
                                List_Certificates.Items.Add(certificate);
                            }
                        }
                    }
                    CollectionViewSource.GetDefaultView(List_Certificates.Items).Refresh();
                    if (List_Certificates.Items.Count > 0)
                    {
                        List_Certificates.SelectedIndex = 0;
                        List_Certificates.Focus();
                        List_Certificates.ScrollIntoView(List_Certificates.SelectedItem);
                    }
                    else
                    {
                        Text_Placeholder.Visibility = Visibility.Visible;
                    }
                }
            }
            catch { }
            finally
            {
                Text_Loading.Visibility = Visibility.Collapsed;
                Panel_Buttons.IsEnabled = true;
            }
        }

        private void CheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (IsInitialized && (e.Source is CheckBox checkbox))
            {
                LoadCertificateList(SelectedStoreName, HideNotValidCerts = checkbox.IsChecked.GetValueOrDefault());
                e.Handled = true;
            }
        }

        private void List_Certificates_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialized)
            {
                Button_Load.IsEnabled = (e.AddedItems.Count > 0);
            }
        }

        private void List_Certificates_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            Button_Load_Click(sender, e);
        }

        private void Button_Load_Click(object sender, RoutedEventArgs e)
        {
            if (IsNotNull(List_Certificates.SelectedItem))
            {
                DialogResult = true;
                s_selectedStoreName = SelectedStoreName;
                s_hideNotValidCerts = HideNotValidCerts;
                Close();
            }
        }

        private void Button_Cancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
