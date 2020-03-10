using System;

namespace NBitcoin.Altcoins.Cuckoo
{
    /// <summary>
    /// Verifies cuckoo proofs.
    /// </summary>
    public static class CuckooVerifier
    {
        /// <summary>
        /// Number of nonces in a proof.
        /// </summary>
        public const int ProofSize = 42;

        // https://github.com/thoughtnetwork/thought/blob/master/src/crypto/cuckoo/verify.cpp
        /// <summary>
        /// Verify a cuckoo proof.
        /// </summary>
        /// <param name="nonces">Proof to verify.</param>
        /// <param name="keys">Keys used for hashing.</param>
        /// <param name="graphSize"></param>
        /// <returns>
        /// <see cref="VerificationResult"/> representing validity of the proof <paramref name="nonces"/>.
        /// </returns>
        public static VerificationResult Verify(uint[] nonces, SiphashKeys keys, int graphSize)
        {
            if (nonces.Length != ProofSize)
            {
                throw new ArgumentException("Incorrect proof format", nameof(nonces));
            }

            uint nnodes = 1U << graphSize;
            uint nedges = 1U << (graphSize - 1);
            uint edgemask = nedges - 1;

            var uvs = new uint[2 * ProofSize];
            uint xor0 = 0;
            uint xor1 = 0;

            var siphash = new Siphash24(keys);

            uint n;

            for (n = 0; n < ProofSize; n++)
            {
                if (nonces[n] > nnodes)
                {
                    return VerificationResult.TooBig;
                }
                if (n != 0 && nonces[n] <= nonces[n - 1])
                {
                    return VerificationResult.TooSmall;
                }

                uvs[2 * n] = siphash.Sipnode(nonces[n], 0, edgemask);
                xor0 ^= uvs[2 * n];
                uvs[2 * n + 1] = siphash.Sipnode(nonces[n], 1, edgemask);
                xor1 ^= uvs[2 * n + 1];
            }
            
            // matching endpoints imply zero xors
            if ((xor0 | xor1) != 0)
            {
                return VerificationResult.NonMatching;
            }

            n = 0;
            uint i = 0;
            uint j;
            do
            {
                for (uint k = j = i; (k = (k + 2) % (2 * ProofSize)) != i;)
                {
                    if (uvs[k] == uvs[i])
                    {
                        if (j != i)
                        {
                            return VerificationResult.Branch;
                        }
                        j = k;
                    }
                }
                if (j == i)
                {
                    return VerificationResult.DeadEnd;
                }

                i = j ^ 1;
                n += 1;
            } while (i != 0);  // must cycle back to start or we would have found branch

            return (n == ProofSize) ? VerificationResult.Ok : VerificationResult.ShortCycle;
        }
    }
}
