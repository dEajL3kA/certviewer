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
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Cache;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

using Microsoft.Win32;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

using static CertViewer.Utilities.NativeMethods;
using static CertViewer.Utilities.Utilities;
using static Farmhash.Sharp.Farmhash;

namespace CertViewer.Utilities
{
    public enum DigestAlgo { MD5, RIPEMD128, RIPEMD160, RIPEMD256, SHA1, BLAKE2_160, BLAKE2_256, BLAKE3, SHA224, SHA256, SHA3_224, SHA3_256 }

    // ==================================================================
    // Untility Methods
    // ==================================================================

    static class Utilities
    {
        private const string REGISTRY_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{815DB72A-522C-4808-8F94-B31039969022}";
        private static readonly Lazy<Regex> CONTROL_CHARACTERS = new Lazy<Regex>(() => new Regex(@"[\u0000-\u001F\u007F]", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled));

        public static StringBuilder Append(StringBuilder sb, string text)
        {
            if ((text = TrimToEmpty(text)).Length > 0)
            {
                return ((sb.Length > 0) ? sb.Append(", ") : sb).Append(text);
            }
            return sb;
        }

        public static void SetText(TextBox textBox, string text, bool trim = true)
        {
            if (IsNotNull(textBox))
            {
                text = trim ? TrimToEmpty(text) : DefaultString(text);
                int maxLength = textBox.MaxLength;
                maxLength = (maxLength > 0) ? Math.Max(maxLength, 4) : int.MaxValue;
                textBox.Text = (text.Length > maxLength) ? $"{text.Substring(0, maxLength - 3)}..." : text;
            }
        }

        public static IDictionary<T, int> ItemsToDictionary<T>(ItemCollection items)
        {
            int index = 0;
            return CollectionUtilities.ReadOnly(items.OfType<T>().ToDictionary(item => item, item => index++));
        }

        public static Tuple<Version, Version, DateTime> GetVersionAndBuildDate()
        {
            try
            {
                Assembly executingAssembly = Assembly.GetExecutingAssembly();
                AssemblyInformationalVersionAttribute appVersion = GetInformationalVersion(executingAssembly);
                AssemblyInformationalVersionAttribute bcVersion = GetInformationalVersion(Assembly.GetAssembly(typeof(Asn1Encodable)));
                return Tuple.Create(TryParseVersion(appVersion),
                    TryParseVersion(bcVersion),
                    TryParseBuildDate(executingAssembly.GetName().Version));
            }
            catch { }
            return Tuple.Create(new Version(0, 0), new Version(0, 0), new DateTime(1970, 1, 1));
        }

        public static Version GetFrameworkVersion()
        {
            try
            {
                Version version = TryParseVersion(GetInformationalVersion(Assembly.GetAssembly(typeof(object))));
                return (version.Major >= 4) ? version : Environment.Version;
            }
            catch { }
            return Environment.Version;
        }

        public static Version TryParseVersion(AssemblyInformationalVersionAttribute attrib)
        {
            if (IsNotNull(attrib))
            {
                Version version;
                if (Version.TryParse(attrib.InformationalVersion.Split('+').First(), out version))
                {
                    if ((version.Build >= 0) && (version.Revision == 0))
                    {
                        return new Version(version.Major, version.Minor, version.Build);
                    }
                    return version;
                }
            }
            return new Version();
        }

        public static AssemblyInformationalVersionAttribute GetInformationalVersion(Assembly assembly)
        {
            if (IsNotNull(assembly))
            {
                return Attribute.GetCustomAttribute(assembly, typeof(AssemblyInformationalVersionAttribute), false) as AssemblyInformationalVersionAttribute;
            }
            return new AssemblyInformationalVersionAttribute(string.Empty);
        }

        public static DateTime TryParseBuildDate(Version version)
        {
            DateTime dateOffset = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            if (IsNotNull(version))
            {
                return dateOffset.Add(new TimeSpan(TimeSpan.TicksPerDay * version.Build + TimeSpan.TicksPerSecond * 2 * version.Revision));
            }
            return dateOffset;
        }

        public static IEnumerable<string> FilterCliArguments(IEnumerable<string> arguments, IList<string> options)
        {
            if (IsNotEmpty(arguments))
            {
                bool flag = false;
                foreach (string argument in arguments)
                {
                    if ((!flag) && argument.StartsWith("--", StringComparison.Ordinal))
                    {
                        if (!(flag = argument.Length <= 2))
                        {
                            options.Add(argument);
                        }
                        continue;
                    }
                    yield return argument;
                }
            }
        }

        public static string ToHexString(BigInteger value)
        {
            if (IsNotNull(value))
            {
                string hexString = value.ToString(16).ToUpperInvariant();
                return (hexString.Length % 2 != 0) ? string.Concat("0", hexString) : hexString;
            }
            return string.Empty;
        }

        public static string ToHexString(byte[] value)
        {
            if (IsNotEmpty(value))
            {
                return Hex.ToHexString(value).ToUpperInvariant();
            }
            return string.Empty;
        }

        public static string EscapeString(string str, bool strict = true)
        {
            if (IsNotEmpty(str))
            {
                if (strict)
                {
                    str = str.Replace("\\", "\\\\").Replace(",", "\\,");
                }
                str = str.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\f", "\\f").Replace("\t", "\\t").Replace("\v", "\\v");
                return CONTROL_CHARACTERS.Value.Replace(str, string.Empty);
            }
            return str;
        }

        public static byte[] ReadFileContents(string fileName, int maxLength)
        {
            if (IsNotEmpty(fileName) && (maxLength > 0))
            {
                try
                {
                    using (FileStream stream = TryOpenFile(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        long length;
                        if ((length = stream.Length) > 0L)
                        {
                            byte[] buffer = new byte[checked((int)Math.Min(length, maxLength))];
                            int bytesRead;
                            if ((bytesRead = Streams.ReadFully(stream, buffer)) > 0)
                            {
                                return (bytesRead >= buffer.Length) ? buffer : Arrays.CopyOfRange(buffer, 0, bytesRead);
                            }
                        }
                    }
                }
                catch { }
            }
            return Array.Empty<byte>();
        }

        public static FileStream TryOpenFile(string filePath, FileMode mode, FileAccess access, FileShare share)
        {
            return DoWithRetry(5, () =>
            {
                return File.Open(filePath, mode, access, share);
            });
        }

        public static void TryCopyToClipboard(string text)
        {
            DoWithRetry(5, () =>
            {
                Clipboard.SetDataObject(text);
                return true;
            });
        }

        public static string TryPasteFromClipboard()
        {
            return DoWithRetry(5, () =>
            {
                return Clipboard.GetText();
            });
        }

        private static T DoWithRetry<T>(int maxTries, Func<T> operation)
        {
            for (int retry = 1; retry < maxTries; ++retry)
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

        public static object GetBaseName(string fileName)
        {
            if (IsNotEmpty(fileName))
            {
                try
                {
                    return Path.GetFileName(fileName);
                }
                catch { }
            }
            return string.Empty;
        }

        public static void Restart(DispatcherTimer timer)
        {
            if (IsNotNull(timer))
            {
                timer.Stop();
                timer.Start();
            }
        }

        public static byte[] CopySubArray(byte[] buffer, int length)
        {
            byte[] newBuffer = Array.Empty<byte>();
            if (IsNotEmpty(buffer))
            {
                int newLength = Math.Min(length, buffer.Length);
                if (newLength > 0)
                {
                    newBuffer = new byte[newLength];
                    Array.Copy(buffer, newBuffer, newLength);
                }
            }
            return newBuffer;
        }

        public static void Rewind(this Stream stream)
        {
            if (IsNotNull(stream))
            {
                stream.Seek(0L, SeekOrigin.Begin);
            }
        }

        public static int GetLength(this Stream stream)
        {
            try
            {
                long length;
                if ((length = stream.Length) <= int.MaxValue)
                {
                    return (int)length;
                }
            }
            catch { }
            return int.MaxValue;
        }

        public static void GetSettingsValue(KeyValueConfigurationCollection settings, string name, Action<string> handler)
        {
            try
            {
                KeyValueConfigurationElement element = settings[name];
                if (IsNotNull(element))
                {
                    string value;
                    if (IsNotEmpty(value = element.Value))
                    {
                        handler(value);
                    }

                }
            }
            catch { }
        }

        public static bool AddIfNotExists<TKey, TValue>(Dictionary<TKey, TValue> dictionary, TKey key, TValue value)
        {
            if (!dictionary.ContainsKey(key))
            {
                dictionary.Add(key, value);
                return true;
            }
            return false;
        }

        public static string GetExeFileName()
        {
            try
            {
                return Assembly.GetExecutingAssembly().Location;
            }
            catch { }
            return string.Empty;
        }

        public static bool CreateProcess(string fileName, string arguments = null)
        {
            if (IsNotEmpty(fileName))
            {
                try
                {
                    using (Process process = new Process())
                    {
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.WindowStyle = ProcessWindowStyle.Normal;
                        process.StartInfo.FileName = fileName;
                        process.StartInfo.Arguments = TrimToEmpty(arguments);
                        return process.Start();
                    }
                }
                catch { }
            }
            return false;
        }

        public static TValue GetValueOrDefault<TKey, TValue>(IDictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue)
        {
            if (IsNotNull(dictionary) && IsNotNull(key))
            {
                TValue value;
                if (dictionary.TryGetValue(key, out value))
                {
                    return value;
                }
            }
            return defaultValue;
        }

        public static void BringWindowToFront(IntPtr hWnd)
        {
            if (hWnd != IntPtr.Zero)
            {
                try
                {
                    using (HandleWrapper wrapper = new HandleWrapper(hWnd))
                    {
                        SetForegroundWindow(wrapper.Handle);
                    }
                }
                catch { }
            }
        }

        public static void DisableMinimizeMaximizeButtons(IntPtr hWnd, bool disableMinimize = true)
        {
            if (hWnd != IntPtr.Zero)
            {
                try
                {
                    using (HandleWrapper wrapper = new HandleWrapper(hWnd))
                    {
                        const int GWL_STYLE = -16;
                        int style;
                        if ((style = GetWindowLong(wrapper.Handle, GWL_STYLE)) != 0)
                        {
                            const int WS_MAXIMIZEBOX = 0x10000, WS_MINIMIZEBOX = 0x20000;
                            SetWindowLong(wrapper.Handle, GWL_STYLE, style & ~(disableMinimize ? WS_MAXIMIZEBOX | WS_MINIMIZEBOX : WS_MAXIMIZEBOX));
                        }
                    }
                }
                catch { }
            }
        }

        public static uint GetWindowProcessId(IntPtr hWnd)
        {
            if (hWnd != IntPtr.Zero)
            {
                try
                {
                    using (HandleWrapper wrapper = new HandleWrapper(hWnd))
                    {
                        uint processId;
                        if (GetWindowThreadProcessId(wrapper.Handle, out processId) != 0)
                        {
                            return processId;
                        }
                    }
                }
                catch { }
            }
            return 0U;
        }

        public static ulong GetUnixTimeSeconds()
        {
            try
            {
                long unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (unixTime >= 0)
                {
                    return (ulong)unixTime;
                }
            }
            catch { }
            return ulong.MinValue;
        }

        public static bool VerifySignature(string message, string signature, string verificationKey)
        {
            try
            {
                byte[] messageData = Encoding.UTF8.GetBytes(message);
                byte[] signatureData = Convert.FromBase64String(signature);
                byte[] keyData = Convert.FromBase64String(verificationKey);
                Ed25519Signer signer = new Ed25519Signer();
                signer.Init(false, new Ed25519PublicKeyParameters(keyData));
                signer.BlockUpdate(messageData, 0, messageData.Length);
                return signer.VerifySignature(signatureData);
            }
            catch { }
            return false;
        }

        public static ulong? ReadRegValue(string valueName)
        {
            try
            {
                using (RegistryKey subkey = Registry.CurrentUser.OpenSubKey(REGISTRY_KEY, false))
                {
                    if (IsNotNull(subkey))
                    {
                        object value = subkey.GetValue(valueName);
                        if (value is int)
                            return (ulong)(int)value;
                        if (value is long)
                            return (ulong)(long)value;
                    }
                }
            }
            catch { }
            return null;
        }

        public static bool WriteRegValue(string valueName, ulong newValue)
        {
            try
            {
                using (RegistryKey subkey = Registry.CurrentUser.CreateSubKey(REGISTRY_KEY, true))
                {
                    if (IsNotNull(subkey))
                    {
                        subkey.SetValue(valueName, (long)newValue, RegistryValueKind.QWord);
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string DefaultString(string text) => IsNotEmpty(text) ? text : string.Empty;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string DefaultString(string text, string defaultString) => IsNotEmpty(text) ? text : defaultString;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNull(object value) => ReferenceEquals(value, null);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotNull(object value) => !IsNull(value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotEmpty(byte[] data) => (!ReferenceEquals(data, null)) && (data.Length > 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotEmpty(string text) => !string.IsNullOrEmpty(text);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotEmpty(SecureString text) => (!ReferenceEquals(text, null)) && (text.Length > 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotEmpty<T>(IList<T> list) => (!ReferenceEquals(list, null)) && (list.Count > 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotEmpty(CollectionView view) => (!ReferenceEquals(view, null)) && (view.Count > 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotEmpty<T>(IEnumerable<T> items) => (!ReferenceEquals(items, null)) && items.Any();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string TrimToEmpty(string text) => (!ReferenceEquals(text, null)) ? text.Trim() : string.Empty;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static async Task DoEvents(Dispatcher dispatcher) => await dispatcher.InvokeAsync(DoEventsHelper, DispatcherPriority.Render);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void DoEventsHelper() { }
    }

    // ==================================================================
    // Trace Log
    // ==================================================================

    public static class TraceLog
    {
        private static readonly Lazy<BooleanSwitch> TRACING = new Lazy<BooleanSwitch>(() => new BooleanSwitch("Tracing", "Enable optional trace outputs", "False"));

        public static void WriteLine(FormattableString message, [CallerMemberName] string callerName = "UnknownFunction")
        {
            try
            {
                Trace.WriteLineIf(TRACING.Value.Enabled, (FormattableString)$"[{callerName}] {message}");
            }
            catch { }
        }
    }

    // ==================================================================
    // Network Helper
    // ==================================================================

    public static class SecurityProtocolTypeExt
    {
        public const SecurityProtocolType Tls13 = (SecurityProtocolType)12288;
    }

    public static class HttpNetClient
    {
        private const string USER_AGENT_STRING = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0";

        static HttpNetClient()
        {
            // Workaround to enable support for "modern" TLS versions in older Windows versions (e.g. Windows 7) where they are disabled by default.
            // This is required, because otherwise the GitHub server will refuse the HTTPS connection!
            // There exist some registry hacks to change the TLS versions that are enabled by default, but we do *not* want to rely on that method.
            try
            {
                try
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolTypeExt.Tls13;
                }
                catch
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                }
            }
            catch { }
        }

        public static Tuple<string, string> DownloadFile(string url)
        {
            TraceLog.WriteLine($"Request URL: {url}");
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.UserAgent = USER_AGENT_STRING;
                request.KeepAlive = false;
                request.CachePolicy = new RequestCachePolicy(RequestCacheLevel.BypassCache);
                request.Timeout = 12000;
                request.ReadWriteTimeout = 8000;
                using (HttpWebResponse response = GetResponseNoThrow(request))
                {
                    TraceLog.WriteLine($"Response status: {response.StatusCode} ({(int)response.StatusCode})");
                    if (IsSuccess(response.StatusCode))
                    {
                        using (Stream responseStream = response.GetResponseStream())
                        {
                            using (StreamReader streamReader = new StreamReader(responseStream, Encoding.UTF8, false))
                            {
                                List<string> lines = new List<string>(2);
                                string line;
                                while (IsNotNull(line = streamReader.ReadLine()))
                                {
                                    if (IsNotEmpty(line = line.Normalize().Trim()))
                                    {
                                        lines.Add(line);
                                        if (lines.Count >= 2)
                                        {
                                            TraceLog.WriteLine($"Response data received successfully.");
                                            return Tuple.Create(lines[0], lines[1]);
                                        }
                                    }
                                }
                            }
                        }
                        TraceLog.WriteLine($"Response is empty or incomplete.");
                    }
                }
            }
            catch (Exception exception)
            {
                TraceLog.WriteLine($"Exception: {exception}");
            }
            return null;
        }

        private static HttpWebResponse GetResponseNoThrow(HttpWebRequest request)
        {
            WebResponse webResponse;
            try
            {
                webResponse = request.GetResponse();
            }
            catch (WebException we)
            {
                if ((we.Status != WebExceptionStatus.ProtocolError) || IsNull(webResponse = we.Response))
                {
                    throw; /*re-throw!*/
                }
            }
            return (HttpWebResponse)webResponse;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsSuccess(HttpStatusCode status) => (status >= HttpStatusCode.OK) && (status < HttpStatusCode.MultipleChoices);
    }

    // ==================================================================
    // Handle Wrapper
    // ==================================================================

    class HandleWrapper : IDisposable
    {
        public HandleRef Handle { get; private set; }

        public HandleWrapper(IntPtr hWnd)
        {
            Handle = new HandleRef(this, hWnd);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public void Dispose() { }
    }

    // ==================================================================
    // Override Cursor
    // ==================================================================

    class OverrideCursor : IDisposable
    {
        private static readonly object m_lock = new object();
        private Once m_restored;
        private readonly Cursor m_previous;

        public OverrideCursor(Cursor cursor)
        {
            lock(m_lock)
            {
                m_previous = Mouse.OverrideCursor;
                Mouse.OverrideCursor = cursor;
            }
        }

        ~OverrideCursor() => Restore();
        
        public void Dispose()
        {
            Restore();
            GC.SuppressFinalize(this);
        }

        public void Restore()
        {
            if (m_restored.Execute())
            {
                Mouse.OverrideCursor = m_previous;
            }
        }
    }

    // ==================================================================
    // Hash Code
    // ==================================================================

    public readonly struct HashCode
    {
        public static readonly HashCode Empty = Compute(string.Empty);

        public readonly ulong Value;

        public HashCode(ulong h) => Value = h;

        public static HashCode Compute(string text) => IsNotNull(text) ? new HashCode(Hash64(text)) : Compute(string.Empty);

        public bool Equals(HashCode other) => (Value == other.Value);

        public override bool Equals(object obj) => (obj is HashCode hashCode) && Equals(hashCode);

        public override int GetHashCode() => Value.GetHashCode();
    }

    // ==================================================================
    // Password Buffer
    // ==================================================================

    class PasswordBuffer : IDisposable
    {
        private Once m_freed;
        private readonly char[] m_buffer = null;
        private readonly GCHandle m_handle;

        public char[] Buffer { get => IsNotNull(m_buffer) ? m_buffer : Array.Empty<char>(); }

        public PasswordBuffer(SecureString text)
        {
            if (IsNotEmpty(text))
            {
                IntPtr temp = IntPtr.Zero;
                try
                {
                    if ((temp = Marshal.SecureStringToBSTR(text)) != IntPtr.Zero)
                    {
                        m_handle = GCHandle.Alloc(m_buffer = new char[text.Length], GCHandleType.Pinned);
                        Marshal.Copy(temp, m_buffer, 0, Buffer.Length);
                    }
                    else
                    {
                        throw new SystemException("Failed to decrypt the SecureString!");
                    }
                }
                finally
                {
                    Marshal.ZeroFreeBSTR(temp);
                }
            }
        }

        ~PasswordBuffer() => Free();

        public void Dispose()
        {
            Free();
            GC.SuppressFinalize(this);
        }

        protected void Free()
        {
            if (m_freed.Execute() && IsNotNull(m_buffer))
            {
                try
                {
                    int byteCount = m_buffer.Length * Marshal.SizeOf<char>();
                    for (int index = 0; index < byteCount; ++index)
                    {
                        Marshal.WriteByte(m_handle.AddrOfPinnedObject(), index, 0);
                    }
                }
                finally
                {
                    m_handle.Free();
                }
            }
        }
    }

    // ==================================================================
    // Font Size Converter
    // ==================================================================

    class FontSizeConverter : IValueConverter
    {
        public double Ratio { get; set; } = 1.0;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double originalFontSize)
            {
                return originalFontSize * Ratio;
            }
            return 1.0;
        }

        public object ConvertBack(object value, Type targetType, object parameter,CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    // ==================================================================
    // Once Flag
    // ==================================================================

    public struct Once
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool Execute() => Interlocked.CompareExchange(ref m_completed, 1, 0) == 0;

        private int m_completed;

        public bool Done => m_completed != 0;
    }

    // ==================================================================
    // Atomic Switch
    // ==================================================================

    public interface ISwitchGuard : IDisposable { }

    public class InvalidSwitchStateException : Exception { }

    public class AtomicSwitch
    {
        private int m_switchState = 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ISwitchGuard Enter()
        {
            if (Interlocked.CompareExchange(ref m_switchState, 1, 0) == 0)
            {
                return new AtomicSwitchGuard(this);
            }
            else
            {
                throw new InvalidSwitchStateException();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator bool(AtomicSwitch instance) => instance.m_switchState != 0;

        class AtomicSwitchGuard : ISwitchGuard
        {
            private readonly AtomicSwitch m_instance;

            private int m_disposed = 0;

            public AtomicSwitchGuard(AtomicSwitch instance)
            {
                m_instance = instance;
            }

            ~AtomicSwitchGuard()
            {
                Dispose(false);
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private void Dispose(bool disposing)
            {
                if (Interlocked.CompareExchange(ref m_disposed, 1, 0) == 0)
                {
                    m_instance.m_switchState = 0;
                }
            }
        }
    }

    // ==================================================================
    // Boolean Converter
    // ==================================================================

    public class BooleanConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool? is_visible = value as bool?;
            return ToVisibility(is_visible.GetValueOrDefault());
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            Visibility? visibility = value as Visibility?;
            return FromVisibility(visibility.GetValueOrDefault(Visibility.Collapsed));
        }

        protected virtual Visibility ToVisibility(bool is_visible)
        {
            return is_visible ? Visibility.Visible : Visibility.Collapsed;
        }

        protected virtual bool FromVisibility(Visibility visibility)
        {
            return visibility == Visibility.Visible;
        }
    }

    public class InvBoolConverter : BooleanConverter
    {
        protected override Visibility ToVisibility(bool is_visible)
        {
            return base.ToVisibility(!is_visible);
        }

        protected override bool FromVisibility(Visibility visibility)
        {
            return !base.FromVisibility(visibility);
        }
    }

    // ==================================================================
    // Native Methods
    // ==================================================================

    [SuppressUnmanagedCodeSecurity]
    static class NativeMethods
    {
        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AddClipboardFormatListener(HandleRef hWnd);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RemoveClipboardFormatListener(HandleRef hWnd);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr GetClipboardOwner();

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint GetWindowThreadProcessId(HandleRef hWnd, out uint processId);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindowEnabled(HandleRef hWnd);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetForegroundWindow(HandleRef hWnd);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, EntryPoint = "GetWindowLongW")]
        public static extern int GetWindowLong(HandleRef hWnd, int nIndex);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, EntryPoint = "SetWindowLongW")]
        public static extern int SetWindowLong(HandleRef hWnd, int nIndex, int dwNewLong);

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern ulong GetTickCount64();
    }
}
