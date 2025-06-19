using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Org.BouncyCastle.Asn1;

namespace CertViewer
{
    public partial class App : Application
    {
        private static class Const
        {
            internal static readonly string MAX_KEY_SIZE = (1U << 16).ToString();
        }

#if !DEBUG
        public App()
        {
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(ExceptionHandler);
        }
#endif

        protected override void OnStartup(StartupEventArgs e)
        {
            const string BOUNCY = "Org.BouncyCastle.";
            try
            {
                Environment.SetEnvironmentVariable(BOUNCY + "EC.Fp_MaxSize", Const.MAX_KEY_SIZE);
                Environment.SetEnvironmentVariable(BOUNCY + "Rsa.MaxSize", Const.MAX_KEY_SIZE);
                Environment.SetEnvironmentVariable(BOUNCY + "Asn1.AllowUnsafeInteger", string.Empty);
                Environment.SetEnvironmentVariable(BOUNCY + "EC.Fp_Certainty", string.Empty);
                Environment.SetEnvironmentVariable(BOUNCY + "Fpe.Disable", string.Empty);
                Environment.SetEnvironmentVariable(BOUNCY + "Fpe.Disable_Ff1", string.Empty);
                Environment.SetEnvironmentVariable(BOUNCY + "Pkcs1.Strict", string.Empty);
                Environment.SetEnvironmentVariable(BOUNCY + "Pkcs12.IgnoreUselessPassword", string.Empty);
                Environment.SetEnvironmentVariable(BOUNCY + "X509.Allow_Non-DER_TBSCert", string.Empty);
            }
            catch { }
            try
            {
                if (Array.Exists(e.Args, str => StrCaseCmp(str, "--render-mode=software")) || StrCaseCmp(Environment.GetEnvironmentVariable("CertViewer.RenderMode"), "software"))
                {
                    RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                }
            }
            catch { }
            GC.KeepAlive(typeof(Asn1Encodable));
        }

#if !DEBUG
        private static void ExceptionHandler(object sender, UnhandledExceptionEventArgs args)
        {
            try
            {
                if (args.ExceptionObject is Exception exception)
                {
                    FatalAppExit(0, $"{exception.GetType().Name}: {exception.Message}");
                }
            }
            catch { }
            Environment.Exit(-1);
        }
#endif

        private static bool StrCaseCmp(string s1, string s2)
        {
            if ((!ReferenceEquals(s1, null)) && (!ReferenceEquals(s2, null)))
            {
                return string.Equals(s1.Trim(), s2.Trim(), StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, EntryPoint="FatalAppExitW")]
        [SuppressUnmanagedCodeSecurity]
        private static extern void FatalAppExit(uint reserved, string message);
    }
}
