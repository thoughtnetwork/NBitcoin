using System;
using System.Security.Cryptography;

namespace NBitcoin.Altcoins.Cuckoo
{
    /// <summary>
    /// Group of keys used for Siphash.
    /// </summary>
    public class SiphashKeys
    {
        /// <summary>
        /// First key.
        /// </summary>
        public readonly ulong k0;
        /// <summary>
        /// Second key.
        /// </summary>
        public readonly ulong k1;
        /// <summary>
        /// Third key.
        /// </summary>
        public readonly ulong k2;
        /// <summary>
        /// Fourth key.
        /// </summary>
        public readonly ulong k3;

        /// <summary>
        /// Initialize a SiphashKeys instance with a group of keys.
        /// </summary>
        /// <param name="k0">First key.</param>
        /// <param name="k1">Second key.</param>
        /// <param name="k2">Third key.</param>
        /// <param name="k3">Fourth key.</param>
        public SiphashKeys(ulong k0, ulong k1, ulong k2, ulong k3)
        {
            this.k0 = k0;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
        }

        /// <summary>
        /// Initialize a SiphashKeys instance from a buffer of keys.
        /// </summary>
        /// <param name="blockHeader">At least 80 bytes of the block header.</param>
        public SiphashKeys(byte[] blockHeader)
        {
            if (blockHeader.Length < 80)
            {
                throw new ArgumentException("Insufficient data to initialize keys", nameof(blockHeader));
            }

            var digest = SHA256.Create().ComputeHash(blockHeader, 0, 80);

            // if the system and buffer endinanness differ, swap the byte order.
            if (!BitConverter.IsLittleEndian)
            {
                var copy = new byte[sizeof(ulong) * 4];
                Array.Copy(digest, copy, copy.Length);
                Array.Reverse(copy, 0, sizeof(ulong));
                Array.Reverse(copy, sizeof(ulong), sizeof(ulong));
                Array.Reverse(copy, sizeof(ulong) * 2, sizeof(ulong));
                Array.Reverse(copy, sizeof(ulong) * 3, sizeof(ulong));
                digest = copy;
            }

            k0 = BitConverter.ToUInt64(digest, 0);
            k1 = BitConverter.ToUInt64(digest, sizeof(ulong));
            k2 = BitConverter.ToUInt64(digest, sizeof(ulong) * 2);
            k3 = BitConverter.ToUInt64(digest, sizeof(ulong) * 3);
        }
    }
}