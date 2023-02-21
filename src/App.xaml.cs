using System;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Org.BouncyCastle.X509;

namespace CertViewer
{
    /// <summary>
    /// Interaktionslogik für "App.xaml"
    /// </summary>
    public partial class App : Application
    {
        public App()
        {
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(ExceptionHandler);
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            typeof(X509Certificate).Equals(null);
            try
            {
                if (Array.Exists(e.Args, str => StrCaseCmp(str, "--render-mode=software")) || StrCaseCmp(Environment.GetEnvironmentVariable("CERTVIEWER_RENDER_MODE"), "software"))
                {
                    RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                }
            }
            catch { }
        }

        private static void ExceptionHandler(object sender, UnhandledExceptionEventArgs args)
        {
            Exception exception;
            if (!ReferenceEquals(exception = args.ExceptionObject as Exception, null))
            {
                MessageBox.Show("Unhandeled exception error:\n\n" + exception.Message, exception.GetType().Name, MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.None, MessageBoxOptions.ServiceNotification);
            }
            Environment.Exit(-1);
        }

        private static bool StrCaseCmp(string s1, string s2)
        {
            if ((!ReferenceEquals(s1, null)) && (!ReferenceEquals(s2, null)))
            {
                return string.Equals(s1.Trim(), s2.Trim(), StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
    }
}
