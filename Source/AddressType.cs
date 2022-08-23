using NBitcoin;

namespace GuessBitcoinKey
{
	internal sealed class AddressType
    {
        public ScriptPubKeyType Type { get; init; }

        public int Threads { get; set; }
    }
}