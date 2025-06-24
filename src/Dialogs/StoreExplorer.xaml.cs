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
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;

using CertViewer.Utilities;
using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class StoreExplorer : Window
    {
        private static readonly object mutex = new object();
        private static StoreName selectedStoreName = StoreName.My;

        private Once hwndInitialized;

        public StoreExplorer()
        {
            InitializeComponent();
            foreach (StoreName storeName in Enum.GetValues(typeof(StoreName)))
            {
                ComboBox_StoreNames.Items.Add(storeName);
            }
            List_Certificates.Items.SortDescriptions.Add(new SortDescription("Subject", ListSortDirection.Ascending));
            List_Certificates.Items.SortDescriptions.Add(new SortDescription("Issuer", ListSortDirection.Ascending));

        }

        protected override void OnContentRendered(EventArgs e)
        {
            if (hwndInitialized.Execute())
            {
                MinWidth = ActualWidth;
                MinHeight = ActualHeight;
                Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(InitializeCertificateView));
                try
                {
                    if (PresentationSource.FromVisual(this) is HwndSource source)
                    {
                        DisableMinimizeMaximizeButtons(source.Handle);
                    }
                }
                catch { }
            }
        }

        private void InitializeCertificateView()
        {
            StoreName storeName;
            lock (mutex)
            {
                storeName = selectedStoreName;
            }
            try
            {
                ComboBox_StoreNames.SelectedIndex = ComboBox_StoreNames.Items.IndexOf(storeName);
            }
            catch { }
        }

        public byte[] SelectedCertificate
        {
            get
            {
                if (!ReferenceEquals(List_Certificates, null))
                {
                    if (List_Certificates.SelectedItem is X509Certificate2 cert)
                    {
                        return cert.RawData;
                    }
                }
                return null;
            }
        }

        private void ComboBox_StoreNames_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.AddedItems.Count > 0)
            {
                if (e.AddedItems[0] is StoreName storeName)
                {
                    using (OverrideCursor busy = new OverrideCursor(Cursors.Wait))
                    {
                        LoadCertificateList(storeName);
                    }
                }
            }
        }

        private async void LoadCertificateList(StoreName storeName)
        {
            try
            {
                List_Certificates.Items.Clear();
                Text_Placeholder.Visibility = Visibility.Collapsed;
                await Task.Yield();
                using (X509Store store = new X509Store(storeName, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadOnly);
                    foreach (X509Certificate2 certificate in store.Certificates)
                    {
                        List_Certificates.Items.Add(certificate);
                    }
                    CollectionViewSource.GetDefaultView(List_Certificates.Items).Refresh();
                }
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
            catch { }
        }

        private void List_Certificates_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            Button_Load.IsEnabled = (e.AddedItems.Count > 0);
        }

        private void List_Certificates_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            Button_Load_Click(sender, e);
        }

        private void Button_Load_Click(object sender, RoutedEventArgs e)
        {
            if (!ReferenceEquals(List_Certificates.SelectedItem, null))
            {
                DialogResult = true;
                if (ComboBox_StoreNames.SelectedItem is StoreName storeName)
                {
                    lock(mutex)
                    {
                        selectedStoreName = storeName;
                    }
                }
                Close();
            }
        }

        private void Button_Cancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

    }
}
