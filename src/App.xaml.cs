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
        public App()
        {
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(ExceptionHandler);
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            const ushort MAX_KEY_SIZE = 32768;
            try
            {
                Environment.SetEnvironmentVariable("Org.BouncyCastle.EC.Fp_MaxSize", MAX_KEY_SIZE.ToString());
                Environment.SetEnvironmentVariable("Org.BouncyCastle.Rsa.MaxSize", MAX_KEY_SIZE.ToString());
                Environment.SetEnvironmentVariable("Org.BouncyCastle.Asn1.AllowUnsafeInteger", string.Empty);
                Environment.SetEnvironmentVariable("Org.BouncyCastle.EC.Fp_Certainty", string.Empty);
                Environment.SetEnvironmentVariable("Org.BouncyCastle.Fpe.Disable", string.Empty);
                Environment.SetEnvironmentVariable("Org.BouncyCastle.Fpe.Disable_Ff1", string.Empty);
                Environment.SetEnvironmentVariable("Org.BouncyCastle.Pkcs1.Strict", string.Empty);
                Environment.SetEnvironmentVariable("Org.BouncyCastle.Pkcs12.IgnoreUselessPassword", string.Empty);
                Environment.SetEnvironmentVariable("Org.BouncyCastle.X509.Allow_Non-DER_TBSCert", string.Empty);
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
            Require(typeof(Asn1Encodable));
        }

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

        private static bool StrCaseCmp(string s1, string s2)
        {
            if ((!ReferenceEquals(s1, null)) && (!ReferenceEquals(s2, null)))
            {
                return string.Equals(s1.Trim(), s2.Trim(), StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void Require(Type _) { }

        [DllImport("kernel32.dll", CallingConvention=CallingConvention.Winapi, ExactSpelling=true, CharSet=CharSet.Unicode, EntryPoint="FatalAppExitW")]
        [SuppressUnmanagedCodeSecurity]
        private static extern void FatalAppExit(uint reserved, string message);
    }
}
