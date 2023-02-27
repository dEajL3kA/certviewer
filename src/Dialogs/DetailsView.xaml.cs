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
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class DetailsView : Window
    {
        private bool m_initialized = false;
        private bool m_scrollbar = false;
        private readonly IEnumerable<KeyValuePair<string, string>> m_items;

        // ==================================================================
        // Constructor
        // ==================================================================

        public DetailsView(IEnumerable<KeyValuePair<string, string>> items)
        {
            InitializeComponent();
            if (IsNotNull(m_items = items))
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
                MaxWidth = ActualWidth;
                MaxHeight = m_scrollbar ? double.PositiveInfinity : ActualHeight;
                if (m_scrollbar)
                {
                    SizeToContent = SizeToContent.Manual;
                }
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
            if (IsNotNull(m_items))
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    string endOfLine = Environment.NewLine;
                    foreach (KeyValuePair<string, string> element in m_items)
                    {
                        sb.Append(element.Key).Append(": ").Append(element.Value).Append(endOfLine);
                    }
                    TryCopyToClipboard(sb.ToString());
                    SystemSounds.Beep.Play();
                }
                catch { }
            }
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
            IEnumerator<KeyValuePair<string, string>> iter = items.GetEnumerator();
            while (iter.MoveNext())
            {
                TextBox textKey = new TextBox() { Text = TruncateText(WrapText(EscapeString(iter.Current.Key,   false)), 1024), Style = keyStyle };
                TextBox textVal = new TextBox() { Text = TruncateText(WrapText(EscapeString(iter.Current.Value, false)), 8448), Style = valStyle };
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

        public static string WrapText(string text, int lineLength = 64)
        {
            if (IsNotEmpty(text) && (lineLength > 0))
            {
                StringBuilder sb = new StringBuilder(text.Length + ((text.Length / lineLength) * Environment.NewLine.Length));
                int offset = 0;
                while (offset < text.Length)
                {
                    int length = Math.Min(text.Length - offset, lineLength);
                    if (offset > 0)
                    {
                        sb.AppendLine();
                    }
                    sb.Append(text.Substring(offset, length));
                    offset += length;
                }
                return sb.ToString();
            }
            return text;
        }
    }
}
