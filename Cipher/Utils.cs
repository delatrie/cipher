using System.Security.Cryptography;

namespace Cipher
{
    class Utils
    {
        private static volatile RNGCryptoServiceProvider _rng;
        internal static RNGCryptoServiceProvider StaticRandomNumberGenerator
        {
            get
            {
                if (_rng == null)
                    _rng = new RNGCryptoServiceProvider();
                return _rng;
            }
        }

        internal static byte[] GenerateRandom(int keySize)
        {
            byte[] key = new byte[keySize];
            StaticRandomNumberGenerator.GetBytes(key);
            return key;
        }
    }
}
