using System.Collections.Generic;
using System.Security.Cryptography;

namespace Cipher.Algorithms
{
    public interface IAlgorithmTransform : ICryptoTransform
    {
        Collector Collector { get; }
    }
}