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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace KeyPairGenerator
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Generating new Ed25519 key-pair, please wait...");
            Console.WriteLine();
            AsymmetricCipherKeyPair keyPair = GenerateEd25519KeyPair();
            if (keyPair.Public is Ed25519PublicKeyParameters publicKeyParameters)
            {
                if (keyPair.Private is Ed25519PrivateKeyParameters secretKeyParameters)
                {
                    byte[] publicKeyData = publicKeyParameters.GetEncoded();
                    byte[] secretKeyData = secretKeyParameters.GetEncoded();

                    Console.WriteLine($"PublicKey: {Convert.ToBase64String(publicKeyData)}");
                    Console.WriteLine($"SecretKey: {Convert.ToBase64String(secretKeyData)}");
                }
            }
        }

        public static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
        {
            SecureRandom random = new SecureRandom();
            Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(random);
            return new AsymmetricCipherKeyPair(privateKey.GeneratePublicKey(), privateKey);
        }
    }
}
