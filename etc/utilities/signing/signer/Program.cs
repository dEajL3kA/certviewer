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
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace MessageSigner
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                throw new ArgumentException("Required argument is missing. The message to be signed must be specified!");
            }

            string signingKeyStr = Environment.GetEnvironmentVariable("MY_SIGNING_KEY");
            if (string.IsNullOrWhiteSpace(signingKeyStr))
            {
                throw new ArgumentException("Environment variable MY_SIGNING_KEY could not be found!");
            }

            Ed25519PrivateKeyParameters signingKey = new Ed25519PrivateKeyParameters(Convert.FromBase64String(signingKeyStr.Trim()));
            string message = args[0].Trim();
            byte[] signature = SignMessage(signingKey, message);

            Console.WriteLine($"Message: \"{message}\"");
            Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");
        }

        public static byte[] SignMessage(Ed25519PrivateKeyParameters secretKey, string message)
        {
            byte[] messageData = Encoding.UTF8.GetBytes(message);
            Ed25519Signer signer = new Ed25519Signer();
            signer.Init(true, secretKey);
            signer.BlockUpdate(messageData, 0, messageData.Length);
            return signer.GenerateSignature();
        }
    }
}
