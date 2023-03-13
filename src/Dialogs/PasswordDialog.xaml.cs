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
using System.Reflection;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class PasswordDialog : WindowEx, UserInputDialog
    {
        // ==================================================================
        // Constructor
        // ==================================================================

        public PasswordDialog(SecureString password, uint currentAttempt, uint maxAttempts)
        {
            InitializeComponent();
            Attempts.Content = ((currentAttempt > 0) && (maxAttempts >= currentAttempt)) ? $"Attempt {currentAttempt} of {maxAttempts}" : string.Empty;
            if (IsNotEmpty(password))
            {
                SetPassword(PasswordBox, password);
                PasswordBox.SelectAll();
            }
            PasswordBox.PasswordChanged += PasswordBox_PasswordChanged;
        }

        public SecureString Password => PasswordBox.SecurePassword;

        // ==================================================================
        // Event Handlers
        // ==================================================================

        protected override void InitializeGui(IntPtr hWnd)
        {
            MinHeight = MaxHeight = ActualHeight;
            MinWidth = ActualWidth;
            SizeToContent = SizeToContent.Manual;
            try
            {
                DisableMinimizeMaximizeButtons(hWnd);
                BringWindowToFront(hWnd);
            }
            catch { }
            PasswordBox.Focus();
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

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            using (SecureString password = PasswordBox.SecurePassword)
            {
                Button_OK.IsEnabled = IsNotEmpty(password);
            }
        }

        private void PasswordBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (((e.Key == Key.Return) || (e.Key == Key.Enter)) && Button_OK.IsEnabled)
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

        // ==================================================================
        // Utility Methods
        // ==================================================================

        private static void SetPassword(PasswordBox control, SecureString password)
        {
            try
            {
                using (SecureString passwordCopy = password.Copy())
                {
                    MethodInfo setSecurePasswordMethod = typeof(PasswordBox).GetMethod("SetSecurePassword", BindingFlags.NonPublic | BindingFlags.Instance, null, new[] { typeof(SecureString) }, null);
                    if (IsNotNull(setSecurePasswordMethod))
                    {
                        setSecurePasswordMethod.Invoke(control, new[] { passwordCopy });
                    }
                }
            }
            catch { }
        }
    }
}
