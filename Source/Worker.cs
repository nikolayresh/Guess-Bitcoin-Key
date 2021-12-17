using Microsoft.Extensions.Hosting;
using NBitcoin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace GuessBitcoinKey
{
    public class Worker : BackgroundService
    {
        private static readonly TimeSpan NotifyPeriod = TimeSpan.FromMinutes(30);
        private const string WalletsFile = "Wallets.txt";
        private const string FoundFile = "Found.txt";
        // you can set your own priority type here
        private const ScriptPubKeyType PriorityType = ScriptPubKeyType.SegwitP2SH;
        private static readonly object FileLocker = new();
        // ReSharper disable once InconsistentNaming
        private static ulong KeysCounter;

        private Task[] _tasks;
        private CancellationTokenSource _cts;
        private HashSet<string> _legacyWallets;
        private HashSet<string> _segwitNativeWallets;
        private HashSet<string> _segwitWallets;

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            Initialize();
            ReadWallets();
            CreateThreadsAndRun();

            return base.StartAsync(cancellationToken);
        }

        private void Initialize()
        {
            RandomUtils.Random = new SecureRandom();
            RandomUtils.UseAdditionalEntropy = false;

            _cts = new CancellationTokenSource();
            _tasks = new Task[Environment.ProcessorCount];

            _legacyWallets = new HashSet<string>();
            _segwitNativeWallets = new HashSet<string>();
            _segwitWallets = new HashSet<string>();
        }

        private void ReadWallets()
        {
            using (StreamReader sr = File.OpenText(Path.Combine(AppContext.BaseDirectory, WalletsFile)))
            {
                string wallet;
                while ((wallet = sr.ReadLine()) != null)
                {
                    wallet = wallet.Trim();
                    if (wallet.Length == 0) continue;

                    if (wallet.StartsWith("3"))
                    {
                        _segwitWallets.Add(wallet);
                        continue;
                    }

                    if (wallet.StartsWith("bc1"))
                    {
                        _segwitNativeWallets.Add(wallet);
                        continue;
                    }

                    _legacyWallets.Add(wallet);
                }
            }

            int wallets = _legacyWallets.Count + _segwitNativeWallets.Count + _segwitWallets.Count;
            WriteToEventLog($"Total count of wallets: {wallets:N0}");
        }

        private ScriptPubKeyType[] CalculatePartitions()
        {
            List<ScriptPubKeyType> partitions = new();

            if (_legacyWallets.Count > 0)
            {
                partitions.Add(ScriptPubKeyType.Legacy);
            }

            if (_segwitNativeWallets.Count > 0)
            {
                partitions.Add(ScriptPubKeyType.Segwit);
            }

            if (_segwitWallets.Count > 0)
            {
                partitions.Add(ScriptPubKeyType.SegwitP2SH);
            }

            return partitions.ToArray();
        }

        private void CommonRunner()
        {
            CancellationToken ct = _cts.Token;

            Mnemonic mnemonic;
            BitcoinAddress address;
            Key key;

            while (!ct.IsCancellationRequested)
            {
                Interlocked.Increment(ref KeysCounter);

                mnemonic = new Mnemonic(Wordlist.English, WordCount.Twelve);
                key = mnemonic.DeriveExtKey().PrivateKey;
                
                // Legacy
                address = key.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
                if (_legacyWallets.Contains(address.ToString()))
                {
                    WriteToEventLog($"You won the lottery! Private key has been found for address: {address}");
                    SavePrivateKey(key, mnemonic, address);
                    continue;
                }

                // Native Segwit
                address = key.GetAddress(ScriptPubKeyType.Segwit, Network.Main);
                if (_segwitNativeWallets.Contains(address.ToString()))
                {
                    WriteToEventLog($"You won the lottery! Private key has been found for address: {address}");
                    SavePrivateKey(key, mnemonic, address);
                    continue;
                }

                // Segwit
                address = key.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);
                if (_segwitWallets.Contains(address.ToString()))
                {
                    WriteToEventLog($"You won the lottery! Private key has been found for address: {address}");
                    SavePrivateKey(key, mnemonic, address);
                }
            }
        }

        private void CreateCommonThreadsAndRun()
        {
            for (int iTask = 0; iTask < Environment.ProcessorCount; iTask++)
            {
                Task task = new(CommonRunner, TaskCreationOptions.LongRunning | TaskCreationOptions.PreferFairness);
                _tasks[iTask] = task;
                task.Start();
            }
        }

        private void CreateThreadsEvenlyAndRun(IReadOnlyList<ScriptPubKeyType> types)
        {
            int threads = Environment.ProcessorCount / types.Count;

            for (int iTask = 0; iTask < Environment.ProcessorCount; iTask++)
            {
                Action action = ResolveThreadAction(types[iTask / threads]);
                Task task = new(action, TaskCreationOptions.LongRunning | TaskCreationOptions.PreferFairness);
                _tasks[iTask] = task;
                task.Start();
            }
        }

        private Action ResolveThreadAction(ScriptPubKeyType type)
        {
            // ReSharper disable once SwitchExpressionHandlesSomeKnownEnumValuesWithExceptionInDefault
            return type switch
            {
                ScriptPubKeyType.Legacy => LegacyRunner,
                ScriptPubKeyType.Segwit => SegwitNativeRunner,
                ScriptPubKeyType.SegwitP2SH => SegwitRunner,
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null),
            };
        }

        private void CreateThreadsAndRun()
        {
            ScriptPubKeyType[] partitions = CalculatePartitions();

            if (partitions.Length == 0)
            {
                // no wallets
                return;
            }

            if (Environment.ProcessorCount < partitions.Length)
            {
                CreateCommonThreadsAndRun();
                return;
            }

            if (Environment.ProcessorCount % partitions.Length == 0)
            {
                CreateThreadsEvenlyAndRun(partitions);
                return;
            }

            CreateComplexThreadsAndRun(partitions);
        }

        private void CreateComplexThreadsAndRun(IEnumerable<ScriptPubKeyType> types)
        {
            int wallets = _legacyWallets.Count + _segwitNativeWallets.Count + _segwitWallets.Count;

            List<AddressType> addressTypes = types.Select(type => new AddressType
            {
                Type = type,
                Threads = (int) Math.Floor(Environment.ProcessorCount * ((double) GetWalletsCount(type) / wallets))
            }).ToList();

            int remainder = Environment.ProcessorCount - addressTypes.Sum(x => x.Threads);
            while (remainder-- != 0)
            {
                HandleRemainderThreads(addressTypes);
            }

            int iType = 0;
            addressTypes.ForEach(x =>
            {
                for (int i = 0; i < x.Threads; i++)
                {
                    Task task = new(ResolveThreadAction(x.Type), TaskCreationOptions.LongRunning | TaskCreationOptions.PreferFairness);
                    _tasks[iType + i] = task;
                    task.Start();
                }

                iType += x.Threads;
            });
        }

        private static void HandleRemainderThreads(IReadOnlyList<AddressType> addressTypes, int index = -1)
        {
            AddressType type;

            if (index !=  -1)
            {
                type = addressTypes[index];
                type.Threads++;
                return;
            }

            type = addressTypes.SingleOrDefault(x => x.Type == PriorityType);

            if (type != null)
            {
                type.Threads++;
                return;
            }

            // recursive call with a random index
            HandleRemainderThreads(addressTypes, RandomNumberGenerator.GetInt32(0, addressTypes.Count));
        }

        private int GetWalletsCount(ScriptPubKeyType type)
        {
            return type switch
            {
                ScriptPubKeyType.Legacy => _legacyWallets.Count,
                ScriptPubKeyType.Segwit => _segwitNativeWallets.Count,
                ScriptPubKeyType.SegwitP2SH => _segwitWallets.Count,
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        private void LegacyRunner()
        {
            CancellationToken ct = _cts.Token;

            Mnemonic mnemonic;
            BitcoinAddress address;
            Key key;

            while (!ct.IsCancellationRequested)
            {
                Interlocked.Increment(ref KeysCounter);

                mnemonic = new Mnemonic(Wordlist.English, WordCount.Twelve);
                key = mnemonic.DeriveExtKey().PrivateKey;
                address = key.GetAddress(ScriptPubKeyType.Legacy, Network.Main);

                if (_legacyWallets.Contains(address.ToString()))
                {
                    WriteToEventLog($"You won the lottery! Private key has been found for address: {address}");
                    SavePrivateKey(key, mnemonic, address);
                }
            }
        }

        private void SegwitNativeRunner()
        {
            CancellationToken ct = _cts.Token;

            Mnemonic mnemonic;
            BitcoinAddress address;
            Key key;

            while (!ct.IsCancellationRequested)
            {
                Interlocked.Increment(ref KeysCounter);

                mnemonic = new Mnemonic(Wordlist.English, WordCount.Twelve);
                key = mnemonic.DeriveExtKey().PrivateKey;
                address = key.GetAddress(ScriptPubKeyType.Segwit, Network.Main);

                if (_segwitNativeWallets.Contains(address.ToString()))
                {
                    WriteToEventLog($"You won the lottery! Private key has been found for address: {address}");
                    SavePrivateKey(key, mnemonic, address);
                }
            }
        }

        private void SegwitRunner()
        {
            CancellationToken ct = _cts.Token;

            Mnemonic mnemonic;
            BitcoinAddress address;
            Key key;

            while (!ct.IsCancellationRequested)
            {
                Interlocked.Increment(ref KeysCounter);

                mnemonic = new Mnemonic(Wordlist.English, WordCount.Twelve);
                key = mnemonic.DeriveExtKey().PrivateKey;
                address = key.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);

                if (_segwitWallets.Contains(address.ToString()))
                {
                    WriteToEventLog($"You won the lottery! Private key has been found for address: {address}");
                    SavePrivateKey(key, mnemonic, address);
                }
            }
        }

        private static void SavePrivateKey(Key key, Mnemonic mnemonic, BitcoinAddress address)
        {
            lock (FileLocker)
            {
                while (true)
                {
                    try
                    {
                        WriteToFile(key, mnemonic, address);
                        break;
                    }
                    catch
                    {
                        // ReSharper disable once RedundantJumpStatement
                        continue;
                    }
                }
            }
        }

        private static void WriteToFile(Key key, Mnemonic mnemonic, BitcoinAddress address)
        {
            using (StreamWriter sw = File.AppendText(Path.Combine(AppContext.BaseDirectory, FoundFile)))
            {
                sw.WriteLine("Private key:");
                   sw.WriteLine($">>> HEX: {key.ToHex()}");
                   sw.WriteLine($">>> WIF (Main): {key.GetBitcoinSecret(Network.Main).ToWif()}");
                   sw.WriteLine($">>> WIF (TestNet): {key.GetBitcoinSecret(Network.TestNet).ToWif()}");
                   sw.WriteLine($">>> WIF (RegTest): {key.GetBitcoinSecret(Network.RegTest).ToWif()}");
                sw.WriteLine($"Mnemonic words: [{mnemonic}]");
                sw.WriteLine($"Address: {address}");

                sw.WriteLine();
                sw.Flush();
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            Task[] activeTasks = _tasks.Where(x => x != null).ToArray();
            if (activeTasks.Length > 0) Task.WaitAll(activeTasks);

            SecureRandom sr = RandomUtils.Random as SecureRandom;
            if (sr != null) sr.Drop();

            return base.StopAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested) 
            {
                await Task.Delay(NotifyPeriod, stoppingToken);

                GC.Collect();
                GC.WaitForPendingFinalizers();

                ulong keys = Interlocked.Read(ref KeysCounter);
                WriteToEventLog($"Total count of keys generated so far: {keys:N0}");
            }
        }

        private static void WriteToEventLog(string message)
        {
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            using (EventLog log = new("Application"))
            {
                log.Source = "Guess Bitcoin Key";
                log.WriteEntry(message, EventLogEntryType.Information);
            }
        }
    }
}