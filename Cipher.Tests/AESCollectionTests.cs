using Cipher.Algorithms.AES;
using NUnit.Framework;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Cipher.Tests
{
    public class AESCollectionTests
    {
        [SetUp]
        public void Setup()
        {
            //this.collector = new 
        }

        [Test]
        [Repeat(10)]
        public void EqualToReferenceImplementation()
        {
            var target = new AES();
            var reference = new AesManaged();
            reference.Key = target.Key;
            reference.IV = target.IV;
            var plainText = "An input string to encrypt!";

            var actualEncrypted = Encrypt(target, plainText);
            var expectedEncrypted = Encrypt(target, plainText);

            Assert.That(actualEncrypted, Is.EqualTo(expectedEncrypted));

            var actualDecrypted = Decrypt(target, actualEncrypted);
            var expectedDecrypted = Decrypt(reference, actualEncrypted);

            Assert.That(actualDecrypted, Is.EqualTo(expectedDecrypted));
        }

        [Test]
        public void BlockTransformationsReturned()
        {
            var target = new AES();
            var reference = new AesManaged();
            reference.Key = target.Key;
            reference.IV = target.IV;
            var plainBytes = CollectorTests.CreateBytes(16);
            var encryptedBytes = Encrypt(reference, plainBytes);
            var transformations = Collector.Encrypt(
                target,
                plainBytes
            );

            Assert.That(transformations, Has.Exactly(18).Items);
            Assert.That(transformations.First(), Is.EqualTo(plainBytes.Concat(Enumerable.Repeat((byte)0, 16))));
            Assert.That(transformations.Last(), Is.EqualTo(encryptedBytes));
        }

        [Test]
        public void LargePlaintextEncrypted()
        {
            var target = new AES();
            var reference = new AesManaged();
            reference.Key = target.Key;
            reference.IV = target.IV;
            var plainBytes = CollectorTests.CreateBytes(256);
            var encryptedBytes = Encrypt(reference, plainBytes);
            var transformations = Collector.Encrypt(
                target,
                plainBytes
            );

            Assert.That(transformations, Has.Exactly(18).Items);
            Assert.That(transformations.First(), Is.EqualTo(plainBytes.Concat(Enumerable.Repeat((byte)0, 16))));
            Assert.That(transformations.Last(), Is.EqualTo(encryptedBytes));
        }

        static byte [] Encrypt(Aes cipher, string plainText)
        {
            var encryptor = cipher.CreateEncryptor(cipher.Key, cipher.IV);
            using (var stream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
            {
                using (var writer = new StreamWriter(cryptoStream))
                    writer.Write(plainText);
                return stream.ToArray();
            }
        }

        static byte[] Encrypt(Aes cipher, byte[] plainBytes)
        {
            var encryptor = cipher.CreateEncryptor(cipher.Key, cipher.IV);
            using var stream = new MemoryStream();
            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
            }
            return stream.ToArray();
        }

        static string Decrypt(Aes cipher, byte[] cipherText)
        {
            var decryptor = cipher.CreateDecryptor(cipher.Key, cipher.IV);
            using (var stream = new MemoryStream(cipherText))
            using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}