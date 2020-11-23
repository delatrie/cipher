using System.Security.Cryptography;

namespace Cipher.Algorithms.AES
{
    public class AESAlgorithm : Rijndael, IAlgorithm
    {
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return NewEncryptor(
                rgbKey,
                this.ModeValue,
                rgbIV,
                this.FeedbackSizeValue,
                AESTransformMode.Decrypt
            );
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return ((IAlgorithm)this).CreateEncryptor(rgbKey, rgbIV);
        }

        IAlgorithmTransform IAlgorithm.CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return NewEncryptor(
                rgbKey,
                this.ModeValue,
                rgbIV,
                this.FeedbackSizeValue,
                AESTransformMode.Encrypt
            );
        }

        public override void GenerateIV()
        {
            this.IVValue = Utils.GenerateRandom(this.BlockSizeValue / 8);
        }

        public override void GenerateKey()
        {
            this.KeyValue = Utils.GenerateRandom(this.KeySizeValue / 8);
        }

        private IAlgorithmTransform NewEncryptor(byte[] rgbKey,
                                               CipherMode mode,
                                               byte[] rgbIV,
                                               int feedbackSize,
                                               AESTransformMode encryptMode)
        {
            if (rgbKey == null)
            {
                rgbKey = Utils.GenerateRandom(this.KeySizeValue / 8);
            }

            if (rgbIV == null)
            {
                rgbIV = Utils.GenerateRandom(this.BlockSizeValue / 8);
            }

            return new AESTransform(
                rgbKey,
                mode,
                rgbIV,
                this.BlockSizeValue,
                feedbackSize,
                this.PaddingValue,
                encryptMode
            );
        }
    }
}
