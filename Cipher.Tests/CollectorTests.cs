using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipher.Tests
{
    class CollectorTests
    {
        [Test]
        public void CollectorCreatedWithNoTransformationsInIt()
        {
            var c = new Collector();

            Assert.That(c.Transformations, Is.Empty);
        }

        [Test]
        public void CollectorInitializedWithRoundIds()
        {
            var c = new Collector(1, 2, 5);

            Assert.That(c.Rounds, Is.EqualTo(new[] { 1, 2, 5 }));
        }

        [Test]
        public void CollectorOfOneBlockWithNoRounds()
        {
            var c = new Collector();
            var bytes = CreateBytes(100);

            var b = c.NewBlock(bytes);

            Assert.That(b.Transformations, Is.EqualTo(new[] { bytes }));
            Assert.That(c.Transformations, Is.EqualTo(new[] { bytes }));
        }

        [Test]
        public void CannotAddUnknownRound()
        {
            var c = new Collector();
            var bytes = CreateBytes(100);

            var b = c.NewBlock(bytes);

            Assert.That(() => b.AddRound(1, bytes), Throws.InstanceOf<ArgumentException>());
        }

        [Test]
        public void CollectorOfOneBlockWithMultipleRounds()
        {
            var c = new Collector(0, 1);
            var plainBytes = CreateBytes(100);
            var round1 = CreateBytes(100);
            var round2 = CreateBytes(100);

            var b = c.NewBlock(plainBytes);
            b.AddRound(0, round1);
            b.AddRound(1, round2);

            Assert.That(b.Transformations, Is.EqualTo(new[] { plainBytes, round1, round2 }));
            Assert.That(c.Transformations, Is.EqualTo(new[] { plainBytes, round1, round2 }));
        }

        [Test]
        public void ByteArraysIsolated()
        {
            var c = new Collector(0);
            var plainBytes = CreateBytes(100);
            var round = CreateBytes(100);
            plainBytes[0] = 255;
            round[0] = 255;

            var b = c.NewBlock(plainBytes);
            b.AddRound(0, round);

            plainBytes[0] = 0;
            round[0] = 0;

            Assert.That(b.Transformations.Select(a => a[0]), Has.All.Not.Zero);
            Assert.That(c.Transformations.Select(a => a[0]), Has.All.Not.Zero);
        }

        [Test]
        public void SameRoundIdNotPossible ()
        {
            var c = new Collector(0);
            var bytes = CreateBytes(100);

            var b = c.NewBlock(bytes);
            b.AddRound(0, bytes);

            Assert.That(() => b.AddRound(0, bytes), Throws.InstanceOf<ArgumentException>());
        }

        [Test]
        public void TwoPlainBlocks()
        {
            var c = new Collector();
            var block1plain = CreateBytes(100);
            var block2plain = CreateBytes(100);

            c.NewBlock(block1plain);
            c.NewBlock(block2plain);

            Assert.That(c.Transformations, Is.EqualTo(new[] { ConcatBytes(block1plain, block2plain) }));
        }

        [Test]
        public void TwoBlocksWithRound()
        {
            var c = new Collector(0);
            var b1 = CreateBytes(100);
            var b1r1 = CreateBytes(100);
            var b2 = CreateBytes(100);
            var b2r1 = CreateBytes(100);

            var block1 = c.NewBlock(b1);
            block1.AddRound(0, b1r1);
            var block2 = c.NewBlock(b2);
            block2.AddRound(0, b2r1);

            Assert.That(block1.Transformations, Is.EqualTo(new[] { b1, b1r1 }));
            Assert.That(block2.Transformations, Is.EqualTo(new[] { b2, b2r1 }));
            Assert.That(
                c.Transformations,
                Is.EqualTo(
                    new []
                    {
                        b1.Concat(b2).ToArray(),
                        b1r1.Concat(b2r1).ToArray()
                    }
                )
            );
        }

        [Test]
        public void RoundCouldBeSkipped()
        {
            var c = new Collector(1, 2);
            var b1 = CreateBytes(2);
            var b1r1 = CreateBytes(2);
            var b1r2 = CreateBytes(2);
            var b2 = CreateBytes(2);
            var b2r1 = CreateBytes(2);
            var b3 = CreateBytes(2);
            var b3r2 = CreateBytes(2);

            var block1 = c.NewBlock(b1);
            block1.AddRound(1, b1r1);
            block1.AddRound(2, b1r2);
            var block2 = c.NewBlock(b2);
            block2.AddRound(1, b2r1);
            var block3 = c.NewBlock(b3);
            block3.AddRound(2, b3r2);

            Assert.That(block1.Transformations, Is.EqualTo(new[] { b1, b1r1, b1r2 }));
            Assert.That(block2.Transformations, Is.EqualTo(new[] { b2, b2r1, b2r1 }));
            Assert.That(block3.Transformations, Is.EqualTo(new[] { b3, b3, b3r2 }));
            Assert.That(
                c.Transformations,
                Is.EqualTo(
                    new[]
                    {
                        ConcatBytes(b1, b2, b3),
                        ConcatBytes(b1r1, b2r1, b3),
                        ConcatBytes(b1r2, b2r1, b3r2)
                    }
                )
            );
        }

        [Test]
        public void RoundCanBeAddedInAnyOrder()
        {
            var c = new Collector(1, 2, 3);
            var b1 = CreateBytes(2);
            var b1r1 = CreateBytes(2);
            var b1r2 = CreateBytes(2);
            var b1r3 = CreateBytes(2);

            var block1 = c.NewBlock(b1);
            block1.AddRound(3, b1r3);
            block1.AddRound(2, b1r2);
            block1.AddRound(1, b1r1);

            Assert.That(block1.Transformations, Is.EqualTo(new[] { b1, b1r1, b1r2, b1r3 }));
            Assert.That(c.Transformations, Is.EqualTo(new[]{ b1, b1r1, b1r2, b1r3 }));
        }

        public static byte[] CreateBytes(int len)
        {
            var buf = new byte[len];
            TestContext.CurrentContext.Random.NextBytes(buf);
            return buf;
        }

        static byte[] ConcatBytes(params byte[][] bytes)
        {
            var len = bytes.Sum(b => b.Length);
            var buf = new byte[len];
            var index = 0;
            foreach (var b in bytes)
            {
                b.CopyTo(buf, index);
                index += b.Length;
            }
            return buf;
        }
    }
}
