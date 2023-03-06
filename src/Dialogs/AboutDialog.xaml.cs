using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;

using static CertViewer.Utilities.Utilities;

namespace CertViewer.Dialogs
{
    public partial class AboutDialog : Window
    {
        private const string MESSAGE = "No system of mass surveillance has existed in any society that we know of to this point that has not been abused!";
        private static readonly Lazy<Version> FRAMEWORK_VERSION = new Lazy<Version>(GetFrameworkVersion);
        private static readonly Lazy<Tuple<Version, Version, DateTime>> PROGRAM_VERSION_INFORMATION = new Lazy<Tuple<Version, Version, DateTime>>(GetVersionAndBuildDate);

        public AboutDialog()
        {
            InitializeComponent();
            Tuple<Version, Version, DateTime> version = PROGRAM_VERSION_INFORMATION.Value;
            VersionNumber_Application.Text = version.Item1.ToString();
            VersionNumber_BouncyCastle.Text = version.Item2.ToString();
            BuildDate.Text = version.Item3.ToString("yyyy-MM-dd");
            VersionNumber_Framework.Text = FRAMEWORK_VERSION.Value.ToString();
        }

        protected override void OnContentRendered(EventArgs e)
        {
            MaxWidth = ActualWidth;
            AboutText.TextWrapping = TextWrapping.Wrap;
            MessageOfTheDay.Text = MESSAGE;
        }

        private void Span_Hyperlink_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton.Equals(MouseButton.Left) && (e.ClickCount > 0))
            {
                if (sender is Run hyperlink)
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo(hyperlink.Text) { UseShellExecute = true });
                    }
                    catch { }
                }
            }
        }

        private void Button_Discard_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
