// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==

using System;
#if !SILVERLIGHT
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
#endif // !SILVERLIGHT

namespace Cipher.Algorithms.AES
{
    /// <summary>
    ///     Managed implementation of the AES algorithm. AES is esentially Rijndael with a fixed block size
    ///     and iteration count, so we just wrap the RijndaelManaged class and allow only 128 bit blocks to
    ///     be used.
    /// </summary>
    public class AES : Aes, IAlgorithm
    {
        private SymmetricAlgorithm m_impl;

        public AES()
        {
            Contract.Ensures(this.m_impl != null);

            this.m_impl = new AESAlgorithm();

            this.m_impl.BlockSize = this.BlockSize;
            this.m_impl.KeySize = this.KeySize;
        }

#if !SILVERLIGHT
        public override int FeedbackSize
        {
            get { return this.m_impl.FeedbackSize; }
            set { this.m_impl.FeedbackSize = value; }
        }
#endif // !SILVERLIGHT

        public override byte[] IV
        {
            get { return this.m_impl.IV; }
            set { this.m_impl.IV = value; }
        }

        public override byte[] Key
        {
            get { return this.m_impl.Key; }
            set { this.m_impl.Key = value; }
        }

        public override int KeySize
        {
            get { return this.m_impl.KeySize; }
            set { this.m_impl.KeySize = value; }
        }

        public override CipherMode Mode
        {
            get { return this.m_impl.Mode; }

            set
            {
                Contract.Ensures(this.m_impl.Mode != CipherMode.CFB && this.m_impl.Mode != CipherMode.OFB);

                // RijndaelManaged will implicitly change the block size of an algorithm to match the number
                // of feedback bits being used. Since AES requires a block size of 128 bits, we cannot allow
                // the user to use the feedback modes, as this will end up breaking that invarient.
                if (value == CipherMode.CFB || value == CipherMode.OFB)
                {
                    throw new CryptographicException("Cryptography_InvalidCipherMode");
                }

                this.m_impl.Mode = value;
            }
        }

        public override PaddingMode Padding
        {
            get { return this.m_impl.Padding; }
            set { this.m_impl.Padding = value; }
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return this.m_impl.CreateDecryptor();
        }

        public override ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
#if !SILVERLIGHT
            if (!ValidKeySize(key.Length * 8))
            {
                throw new ArgumentException("Cryptography_InvalidKeySize", "key");
            }
            if (iv != null && iv.Length * 8 != this.BlockSizeValue)
            {
                throw new ArgumentException("Cryptography_InvalidIVSize", "iv");
            }
#endif

            return this.m_impl.CreateDecryptor(key, iv);
        }


        public override ICryptoTransform CreateEncryptor()
        {
            return this.m_impl.CreateEncryptor();
        }

        public override ICryptoTransform CreateEncryptor(byte[] key, byte[] iv)
        {
            return ((IAlgorithm)this).CreateEncryptor(key, iv);
        }

        IAlgorithmTransform IAlgorithm.CreateEncryptor(byte[] key, byte[] iv)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
#if !SILVERLIGHT
            if (!ValidKeySize(key.Length * 8))
            {
                throw new ArgumentException("Cryptography_InvalidKeySize", "key");
            }
            if (iv != null && iv.Length * 8 != this.BlockSizeValue)
            {
                throw new ArgumentException("Cryptography_InvalidIVSize", "iv");
            }
#endif // SILVERLIGHT

            return ((IAlgorithm)this.m_impl).CreateEncryptor(key, iv);
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    (this.m_impl as IDisposable).Dispose();
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        public override void GenerateIV()
        {
            this.m_impl.GenerateIV();
        }

        public override void GenerateKey()
        {
            this.m_impl.GenerateKey();
        }
    }
}