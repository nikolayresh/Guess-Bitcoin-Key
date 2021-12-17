using NBitcoin;
using System;
using System.Security.Cryptography;

namespace GuessBitcoinKey
{
    internal class SecureRandom : IRandom
    {
        private RNGCryptoServiceProvider _rng = new();

        public void GetBytes(byte[] output)
        {
            _rng.GetBytes(output);
        }

        public void GetBytes(Span<byte> output)
        {
            _rng.GetBytes(output);
        }

        public void Drop()
        {
            if (_rng != null)
            {
                _rng.Dispose();
                _rng = null;
            }
        }
    }
}