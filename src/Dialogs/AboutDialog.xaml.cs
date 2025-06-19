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
using System.Diagnostics;
using System.IO;
using System.Media;
using System.Reflection;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
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
            CopyrightYear.Text = Math.Max(CurrentYear, version.Item3.Year).ToString();
            BuildDate.Text = version.Item3.ToString("yyyy-MM-dd");
            VersionNumber_Framework.Text = FRAMEWORK_VERSION.Value.ToString();
            try
            {
                if (IsThatSeasonAgain)
                {
                    Logo.Source = (ImageSource) FindResource("ImageSource_Logo2");
                    PlaySound("hohoho.wav");
                }
                else
                {
                    SystemSounds.Asterisk.Play();
                }
            }
            catch { }
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

        private static void PlaySound(string fileName)
        {
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(string.Concat("CertViewer.Resources.", fileName)))
                {
                    new SoundPlayer(stream).Play();
                }
            }
            catch { }
        }

        private static int CurrentYear
        {
            get
            {
                try
                {
                    return Math.Max(2000, Math.Min(2999, DateTime.UtcNow.Year));
                }
                catch { }
                return DateTime.MinValue.Year;
            }
        }

        private static bool IsThatSeasonAgain
        {
            get
            {
                try
                {
                    DateTime now = DateTime.Now;
                    return (now.Month == 12) && (now.Day >= 24) && (now.Day <= 26);
                }
                catch { }
                return false;
            }
        }
    }
}
