using System;
using System.Collections.Generic;
using System.Linq;

namespace Cipher
{
    public class Block
    {
        internal Block(Collector collector, byte[] plain)
        {
            this.collector = collector;
            this.plain = plain.ToArray();
        }

        public void AddRound(int roundId, byte[] roundOutput)
        {
            if (!this.collector.Rounds.Contains(roundId))
                throw new ArgumentException($"Unknown round with ID {roundId}");
            if (this.transformations.ContainsKey(roundId))
                throw new ArgumentException($"Duplicate round with ID {roundId}");
            this.transformations.Add(roundId, roundOutput.ToArray());
        }

        public IEnumerable<byte[]> Transformations
        {
            get
            {
                yield return this.plain;
                byte[] current = this.plain;
                foreach (var roundId in this.collector.Rounds)
                {
                    if (this.transformations.ContainsKey(roundId))
                    {
                        current = this.transformations[roundId];
                    }
                    yield return current;
                }
            }
        }

        readonly Collector collector;
        readonly byte[] plain;
        readonly Dictionary<int, byte[]> transformations = new Dictionary<int, byte[]>();
    }
}
