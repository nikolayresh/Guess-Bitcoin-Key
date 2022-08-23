namespace GuessBitcoinKey
{
	internal static class Extensionscs
	{
		internal static void Increment(this byte[] data)
		{
			int i = data.Length - 1;

			while (i >= 0 && ++data[i] == byte.MinValue)
			{
				i--;
			}
		}
	}
}
