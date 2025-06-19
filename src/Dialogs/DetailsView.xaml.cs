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
using System.Collections.Generic;
using System.Linq;
using System.Media;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class DetailsView : WindowEx
    {
        private bool m_scrollbar = false, m_resizeEnabled = false;

        private readonly IDictionary<TabItem, int> m_tabs;
        private readonly ISet<TabItem> m_tabInitialized;
        private readonly IEnumerable<KeyValuePair<string, string>> m_items;
        private readonly string m_asn1Data, m_pemData;

        private static readonly Lazy<Regex> BINARY_STRING = new Lazy<Regex>(() => new Regex(@"^[A-Za-z0-9]+$", RegexOptions.Singleline | RegexOptions.Compiled));

        // ==================================================================
        // Constructor
        // ==================================================================

        public DetailsView(IEnumerable<KeyValuePair<string, string>> items, string asn1Data = null, string pemData = null)
        {
            InitializeComponent();
            m_tabs = ItemsToDictionary<TabItem>(TabControl.Items);
            m_tabInitialized = new HashSet<TabItem>() { Tab_Details };
            if (IsNotNull(m_items = items))
            {
                CreateElements(items);
            }
            if (IsNotEmpty(m_asn1Data = asn1Data))
            {
                Tab_Details.Visibility = Tab_Asn1Data.Visibility = Visibility.Visible;
                Tab_Asn1Data.IsEnabled = true;
            }
            if (IsNotEmpty(m_pemData = pemData))
            {
                Tab_Details.Visibility = Tab_PemData.Visibility = Visibility.Visible;
                Tab_PemData.IsEnabled = true;
            }
        }

        // ==================================================================
        // Event Handlers
        // ==================================================================

        protected override void InitializeGui(IntPtr hWnd)
        {
            MinHeight = ActualHeight;
            MinWidth = ActualWidth;
            MaxWidth = ActualWidth;
            MaxHeight = m_scrollbar ? double.PositiveInfinity : ActualHeight;
            SizeToContent = SizeToContent.Manual;
            try
            {
                DisableMinimizeMaximizeButtons(hWnd);
                BringWindowToFront(hWnd);
            }
            catch { }
            Keyboard.ClearFocus();
        }

        private void ScrollView_Loaded(object sender, RoutedEventArgs e)
        {
            if (ScrollView.ComputedVerticalScrollBarVisibility.Equals(Visibility.Visible))
            {
                m_scrollbar = true;
                ScrollView.Padding = new Thickness(0, 0, 6, 0);
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
                switch (GetValueOrDefault(m_tabs, TabControl.SelectedItem as TabItem, 0))
                {
                    case 0:
                        StringBuilder sb = new StringBuilder();
                        foreach (KeyValuePair<string, string> element in m_items)
                        {
                            sb.Append(element.Key).Append(": ").AppendLine(element.Value);
                        }
                        TryCopyToClipboard(sb.ToString());
                        goto default;
                    case 1:
                        TryCopyToClipboard(m_asn1Data);
                        goto default;
                    case 2:
                        TryCopyToClipboard(m_pemData);
                        goto default;
                    default:
                        SystemSounds.Beep.Play();
                        break;
                }
            }
            catch { }
        }

        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                foreach (TabItem item in e.AddedItems.OfType<TabItem>())
                {
                    if (m_tabInitialized.Add(item))
                    {
                        switch (GetValueOrDefault(m_tabs, TabControl.SelectedItem as TabItem, 0))
                        {
                            case 1:
                                TextBox_Asn1Data.Text = m_asn1Data;
                                goto default;
                            case 2:
                                TextBox_PemData.Text = m_pemData;
                                goto default;
                            default:
                                if (!m_resizeEnabled)
                                {
                                    EnableResize(608, 288);
                                    m_resizeEnabled = true;
                                }
                                break;
                        }
                    }
                }
            }
            catch { }
        }

        // ==================================================================
        // Internal Methods
        // ==================================================================

        private void CreateElements(IEnumerable<KeyValuePair<string, string>> items)
        {
            Style keyStyle = FindResource("KeyStyle") as Style;
            Style valStyle = FindResource("ValueStyle") as Style;
            DatailsPane.Children.Clear();
            IEnumerator<KeyValuePair<string, string>> iter = items.GetEnumerator();
            while (iter.MoveNext())
            {
                TextBox textKey = new TextBox() { Text = TruncateText(WrapText(EscapeString(iter.Current.Key,   false)), 1024), Style = keyStyle };
                TextBox textVal = new TextBox() { Text = TruncateText(WrapText(EscapeString(iter.Current.Value, false)), 8448), Style = valStyle };
                if (DatailsPane.Children.Count > 0)
                {
                    DatailsPane.RowDefinitions.Add(new RowDefinition() { MinHeight = 2 });
                }
                int rowIndex = DatailsPane.RowDefinitions.Count;
                DatailsPane.RowDefinitions.Add(new RowDefinition());
                DatailsPane.Children.Add(textKey);
                DatailsPane.Children.Add(textVal);
                Grid.SetColumn(textKey, 0);
                Grid.SetColumn(textVal, 1);
                Grid.SetRow(textKey, rowIndex);
                Grid.SetRow(textVal, rowIndex);
            }
        }

        private void EnableResize(double width, double height)
        {
            MaxWidth = MaxHeight = double.PositiveInfinity;
            MinWidth = Math.Max(MinWidth, width);
            MinHeight = Math.Max(MinHeight, height);
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
            if (BINARY_STRING.Value.IsMatch(text = TrimToEmpty(text)) && (lineLength > 0))
            {
                StringBuilder sb = new StringBuilder(text.Length + (text.Length / lineLength * Environment.NewLine.Length));
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
