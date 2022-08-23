using System.Security.Cryptography;

namespace GuessBitcoinKey
{
	internal static class RandomGenerator
	{
		private static readonly RandomNumberGenerator RNG = RandomNumberGenerator.Create();

		internal static byte[] GetNextBytes(int count)
		{
			byte[] data = new byte[count];
			RNG.GetBytes(data);
			return data;
		}
	}
}
