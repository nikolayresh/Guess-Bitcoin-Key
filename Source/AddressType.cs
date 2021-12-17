using NBitcoin;

namespace GuessBitcoinKey
{
    internal class AddressType
    {
        public ScriptPubKeyType Type { get; init; }

        public int Threads { get; set; }
    }
}