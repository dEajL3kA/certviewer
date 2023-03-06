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
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;

using static CertViewer.Utilities.Utilities;
using static CertViewer.Utilities.NativeMethods;

namespace CertViewer.Dialogs
{
    public partial class PasswordDialog : Window
    {
        private bool m_initialized = false;

        public PasswordDialog(string password, uint currentAttempt, uint maxAttempts)
        {
            InitializeComponent();
            Attempts.Content = ((currentAttempt > 0) && (maxAttempts >= currentAttempt)) ? $"Attempt {currentAttempt} of {maxAttempts}" : string.Empty;
            if (IsNotEmpty(password))
            {
                PasswordBox.Password = password;
                PasswordBox.SelectAll();
            }
        }

        public string Password
        {
            get
            {
                return PasswordBox.Password;
            }
        }

        // ==================================================================
        // Event Handlers
        // ==================================================================

        protected override void OnContentRendered(EventArgs e)
        {
            base.OnContentRendered(e);
            if (!m_initialized)
            {
                m_initialized = true;
                MinHeight = MaxHeight = ActualHeight;
                MinWidth = ActualWidth;
                SizeToContent = SizeToContent.Manual;
                try
                {
                    SetForegroundWindow(new WindowInteropHelper(this).Handle);
                }
                catch { }
                PasswordBox.Focus();
            }
        }

        public bool? ShowDialog(IDisposable busy)
        {
            Dispatcher.InvokeAsync(() => busy.Dispose(), DispatcherPriority.Background);
            return ShowDialog();
        }

        private void Button_OK_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void Button_Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void PasswordBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if ((e.Key == Key.Return) || (e.Key == Key.Enter))
            {
                e.Handled = true;
                Button_OK_Click(sender, e);
            }
        }

        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                e.Handled = true;
                Button_Cancel_Click(sender, e);
            }
        }
    }
}
