using System;
using System.Collections.Generic;
using System.Text;
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
        private IList<KeyValuePair<TextBox, TextBox>> m_controls = new List<KeyValuePair<TextBox, TextBox>>();

        // ==================================================================
        // Constructor
        // ==================================================================

        public DetailsView(IEnumerable<KeyValuePair<string, string>> items)
        {
            InitializeComponent();
            if (!ReferenceEquals(items, null))
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
                MaxHeight = MinHeight = ActualHeight;
                MinWidth = ActualWidth;
            }
        }


        private void ScrollView_Loaded(object sender, RoutedEventArgs e)
        {
            if (ScrollView.ComputedVerticalScrollBarVisibility.Equals(Visibility.Visible))
            {
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
                StringBuilder sb = new StringBuilder();
                string eol = Environment.NewLine;
                foreach (KeyValuePair<TextBox, TextBox> element in m_controls)
                {
                    sb.Append(element.Key.Text).Append(": ").Append(element.Value.Text).Append(eol);
                }
                Clipboard.SetText(sb.ToString());
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
                TextBox textKey = new TextBox() { Text = iter.Current.Key,   Style = keyStyle };
                TextBox textVal = new TextBox() { Text = iter.Current.Value, Style = valStyle };
                if (Layout.Children.Count > 0)
                {
                    Layout.RowDefinitions.Add(new RowDefinition() { MinHeight = 4 });
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
    }
}
