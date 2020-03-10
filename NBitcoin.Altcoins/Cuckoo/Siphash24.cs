namespace NBitcoin.Altcoins.Cuckoo
{
    class Siphash24
    {
        private readonly SiphashKeys keys;

        private ulong v0;
        private ulong v1;
        private ulong v2;
        private ulong v3;

        private static ulong ROTL(ulong x, int b)
        {
            return (x << b) | (x >> (64 - b));
        }

        private void Sipround()
        {
            v0 += v1;
            v2 += v3;
            v1 = ROTL(v1, 13);
            v3 = ROTL(v3, 16);
            v1 ^= v0;
            v3 ^= v2;
            v0 = ROTL(v0, 32);
            v2 += v1;
            v0 += v3;
            v1 = ROTL(v1, 17);
            v3 = ROTL(v3, 21);
            v1 ^= v2;
            v3 ^= v0;
            v2 = ROTL(v2, 32);
        }

        public Siphash24(SiphashKeys keys)
        {
            this.keys = keys;
        }

        public ulong Hash(ulong nonce)
        {
            v0 = keys.k0;
            v1 = keys.k1;
            v2 = keys.k2;
            v3 = keys.k3 ^ nonce;

            Sipround(); Sipround();
            v0 ^= nonce;
            v2 ^= 0xff;
            Sipround(); Sipround();
            Sipround(); Sipround();

            return (v0 ^ v1) ^ (v2 ^ v3);
        }

        public uint Sipnode(uint nonce, uint uorv, uint edgemask)
        {
            return (uint)(Hash(2 * nonce + uorv) & edgemask) << 1 | uorv;
        }
    }
}
