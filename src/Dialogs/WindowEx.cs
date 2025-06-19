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
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;

using CertViewer.Utilities;
using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public abstract class WindowEx : Window
    {
        protected IntPtr Hwnd { get; private set; } = IntPtr.Zero;

        private Once m_wndInitialized;
        private Once m_guiInitialized;

        protected bool IsWndInitialized => m_wndInitialized.Done;
        protected bool IsGuiInitialized => m_guiInitialized.Done;

        // ==================================================================
        // Event Handlers
        // ==================================================================

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            try
            {
                if (PresentationSource.FromVisual(this) is HwndSource source)
                {
                    Hwnd = source.Handle;
                    source.AddHook(WndProc);
                    if (m_wndInitialized.Execute())
                    {
                        InitializeWnd(source);
                    }
                }
            }
            catch { }
        }

        protected override void OnContentRendered(EventArgs e)
        {
            base.OnContentRendered(e);
            if (m_guiInitialized.Execute())
            {
                InitializeGui(Hwnd);
            }
        }

        // ==================================================================
        // Public Methods
        // ==================================================================

        public bool? ShowDialog(IDisposable busy)
        {
            if (IsNotNull(busy))
            {
                Dispatcher.InvokeAsync(() => busy.Dispose(), DispatcherPriority.Background);
            }
            return ShowDialog();
        }

        // ==================================================================
        // Virtual Methods
        // ==================================================================

        protected abstract void InitializeGui(IntPtr hWnd);

        protected virtual void InitializeWnd(HwndSource source) { }

        protected virtual IntPtr WndProc(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            return IntPtr.Zero;
        }
    }
}
