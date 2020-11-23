using Cipher.Algorithms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Cipher
{
    public class Collector
    {
        public Collector(params int[] roundIds)
        {
            this.Rounds = roundIds;
        }

        public IReadOnlyList<int> Rounds { get; }

        public Block NewBlock(byte[] plain)
        {
            var block = new Block(this, plain);
            this.blocks.Add(block);
            return block;
        }

        public IEnumerable<byte[]> Transformations
        {
            get
            {
                return ZipMany(
                    this.blocks.Select(b => b.Transformations)
                ).Select(e => e.Aggregate(Enumerable.Empty<byte>(), (a, c) => a.Concat(c), a => a.ToArray()));
            }
        }

        public static IEnumerable<byte[]> Encrypt(IAlgorithm algorithm, byte[] plainBytes)
        {
            var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV);
            using (var stream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
            }
            return encryptor.Collector.Transformations;
        }

        static IEnumerable<IEnumerable<byte[]>> ZipMany(IEnumerable<IEnumerable<byte[]>> transformations)
        {
            using (var ens = new ParallelEnumerable(transformations))
            {
                if (ens.Enumerators.Any())
                {
                    while (ens.Enumerators.All(e => e.MoveNext()))
                    {
                        yield return ens.Enumerators.Select(e => e.Current);
                    }
                }
            }
        }

        readonly List<Block> blocks = new List<Block>();

        class ParallelEnumerable : IDisposable
        {
            public ParallelEnumerable(IEnumerable<IEnumerable<byte[]>> enums)
            {
                this.Enumerators = enums.Select(e => e.GetEnumerator()).ToArray();
            }

            public IEnumerator<byte[]>[] Enumerators { get; }

            public void Dispose()
            {
                foreach (var e in this.Enumerators)
                {
                    e.Dispose();
                }
            }
        }
    }
}
