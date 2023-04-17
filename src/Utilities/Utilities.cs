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
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

using static Farmhash.Sharp.Farmhash;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Encoders;

using static CertViewer.Utilities.NativeMethods;
using static CertViewer.Utilities.Utilities;

namespace CertViewer.Utilities
{
    public enum DigestAlgo { MD5, RIPEMD128, RIPEMD160, RIPEMD256, SHA1, BLAKE2_160, BLAKE2_256, BLAKE3, SHA224, SHA256, SHA3_224, SHA3_256 }

    // ==================================================================
    // Untility Methods
    // ==================================================================

    static class Utilities
    {
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

        public static IEnumerable<string> FilterCliArguments(IEnumerable<string> arguments)
        {
            if (IsNotEmpty(arguments))
            {
                bool flag = false;
                foreach (string argument in arguments)
                {
                    if ((!flag) && argument.StartsWith("--", StringComparison.Ordinal))
                    {
                        if (argument.Equals("--", StringComparison.Ordinal))
                        {
                            flag = true;
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
            return DoWithRetry(8, () =>
            {
                return File.Open(filePath, mode, access, share);
            });
        }

        public static void TryCopyToClipboard(string text)
        {
            DoWithRetry(8, () =>
            {
                Clipboard.SetText(text);
                return true;
            });
        }

        public static string TryPasteFromClipboard()
        {
            return DoWithRetry(8, () =>
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string DefaultString(string text) => IsNotEmpty(text) ? text : string.Empty;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string DefaultString(string text, string defaultString) => IsNotEmpty(text) ? text : defaultString;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNotNull(object value) => !ReferenceEquals(value, null);

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

        public readonly ulong h;

        public HashCode(ulong h) => this.h = h;

        public static HashCode Compute(string text) => IsNotNull(text) ? new HashCode(Hash64(text)) : Compute(string.Empty);

        public bool Equals(HashCode other) => (h == other.h);

        public override bool Equals(object obj) => (obj is HashCode hashCode) && Equals(hashCode);

        public override int GetHashCode() => h.GetHashCode();
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
