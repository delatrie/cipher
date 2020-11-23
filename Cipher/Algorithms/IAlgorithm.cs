namespace Cipher.Algorithms
{
    public interface IAlgorithm
    {
        byte[] Key { get; set; }
        byte[] IV { get; set; }
        IAlgorithmTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV);
    }
}
