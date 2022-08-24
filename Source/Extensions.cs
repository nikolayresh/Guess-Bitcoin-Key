namespace GuessBitcoinKey
{
	internal static class Extensions
	{
		internal static void Increment(this byte[] data)
		{
			int i = data.Length - 1;
			while (i >= 0 && ++data[i] == 0)
			{
				i--;
			}
		}
	}
}