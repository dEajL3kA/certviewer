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
using System.Media;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace CertViewer.Dialogs
{
    /// <summary>
    /// Interaktionslogik für DNViewer.xaml
    /// </summary>
    public partial class DetailsView : Window
    {
        private bool m_initialized = false;
        private bool m_scrollbar = false;
        private IList<KeyValuePair<TextBox, TextBox>> m_controls = new List<KeyValuePair<TextBox, TextBox>>();

        // ==================================================================
        // Constructor
        // ==================================================================

        public DetailsView(IEnumerable<KeyValuePair<string, string>> items)
        {
            InitializeComponent();
            if (IsNotNull(items))
            {
                CreateElements(items);
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
                MinHeight = ActualHeight;
                MinWidth = ActualWidth;
                SizeToContent = m_scrollbar ? SizeToContent.Manual : SizeToContent.Height;
                MaxWidth = double.PositiveInfinity;
                MaxHeight = m_scrollbar ? double.PositiveInfinity : ActualHeight;
            }
        }


        private void ScrollView_Loaded(object sender, RoutedEventArgs e)
        {
            if (ScrollView.ComputedVerticalScrollBarVisibility.Equals(Visibility.Visible))
            {
                ScrollView.Padding = new Thickness(0, 0, 6, 0);
                m_scrollbar = true;
            }
        }

        private void Button_Discard_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void Button_CopyToCLipboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                string eol = Environment.NewLine;
                foreach (KeyValuePair<TextBox, TextBox> element in m_controls)
                {
                    sb.Append(element.Key.Text).Append(": ").Append(element.Value.Text).Append(eol);
                }
                TryCopyToClipboard(sb.ToString());
                SystemSounds.Beep.Play();
            }
            catch { }
        }

        public bool? ShowDialog(IDisposable busy)
        {
            Dispatcher.InvokeAsync(() => busy.Dispose(), DispatcherPriority.Background);
            return ShowDialog();
        }

        // ==================================================================
        // Internal Methods
        // ==================================================================

        private void CreateElements(IEnumerable<KeyValuePair<string, string>> items)
        {
            Style keyStyle = FindResource("KeyStyle") as Style;
            Style valStyle = FindResource("ValueStyle") as Style;
            Layout.Children.Clear();
            m_controls.Clear();
            IEnumerator<KeyValuePair<string, string>> iter = items.GetEnumerator();
            while (iter.MoveNext())
            {
                TextBox textKey = new TextBox() { Text = TruncateText(iter.Current.Key,   1024), Style = keyStyle };
                TextBox textVal = new TextBox() { Text = TruncateText(iter.Current.Value, 4096), Style = valStyle };
                if (Layout.Children.Count > 0)
                {
                    Layout.RowDefinitions.Add(new RowDefinition() { MinHeight = 2 });
                }
                int rowIndex = Layout.RowDefinitions.Count;
                Layout.RowDefinitions.Add(new RowDefinition());
                Layout.Children.Add(textKey);
                Layout.Children.Add(textVal);
                Grid.SetColumn(textKey, 0);
                Grid.SetColumn(textVal, 1);
                Grid.SetRow(textKey, rowIndex);
                Grid.SetRow(textVal, rowIndex);
                m_controls.Add(new KeyValuePair<TextBox, TextBox>(textKey, textVal));
            }
        }

        // ==================================================================
        // Utility Methods
        // ==================================================================

        private static string TruncateText(string text, int maxLength)
        {
            if (IsNotNull(text) && (maxLength > 3))
            {
                return (text.Length > maxLength) ? $"{text.Substring(0, maxLength - 3)}..." : text;
            }
            return string.Empty;
        }

        private static void TryCopyToClipboard(string text)
        {
            if (IsNotEmpty(text))
            {
                DoWithRetry(32, () => { Clipboard.SetText(text); return true; });
            }
        }

        private static T DoWithRetry<T>(int maxTries, Func<T> operation)
        {
            for (int retry = 0; retry < maxTries; ++retry)
            {
                try
                {
                    return operation();
                }
                catch { }
                Thread.Sleep(retry);
            }
            return operation();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotEmpty(string text)
        {
            return !string.IsNullOrEmpty(text);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotNull(object value)
        {
            return !ReferenceEquals(value, null);
        }
    }
}
