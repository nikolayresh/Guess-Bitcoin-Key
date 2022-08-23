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
        private const int ScanRange = (1 << 20) + 1;
        private const int EntropyLength = 16;
        private static readonly TimeSpan NotifyPeriod = TimeSpan.FromMinutes(30);
        private const string WalletsFile = "Wallets.txt";
        private const string FoundFile = "Found.txt";
        // you can set your own priority type here
        private const ScriptPubKeyType PriorityType = ScriptPubKeyType.SegwitP2SH;
        private static readonly object FileLock = new();
        // ReSharper disable once InconsistentNaming
        private static ulong ProgressTracker;

        private Task[] _tasks;
        private CancellationTokenSource _cts;
        private HashSet<string> _legacyWallets;
        private HashSet<string> _nativeSegwitWallets;
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
            ProgressTracker = 0UL;

            _cts = new CancellationTokenSource();
            _tasks = new Task[Environment.ProcessorCount];

            _legacyWallets = new HashSet<string>();
            _nativeSegwitWallets = new HashSet<string>();
            _segwitWallets = new HashSet<string>();
        }

        private void ReadWallets()
        {
            using (StreamReader file = File.OpenText(Path.Combine(AppContext.BaseDirectory, WalletsFile)))
            {
                string wallet;
                while ((wallet = file.ReadLine()) != null)
                {
                    wallet = wallet.Trim();
                    if (wallet.Length == 0)
					{
                        continue;
					}

                    if (wallet.StartsWith("3"))
                    {
                        _segwitWallets.Add(wallet);
                        continue;
                    }

                    if (wallet.StartsWith("bc1"))
                    {
                        _nativeSegwitWallets.Add(wallet);
                        continue;
                    }

                    if (wallet.StartsWith("1"))
                    {
                        _legacyWallets.Add(wallet);
                    }
                }
            }

            int wallets = _legacyWallets.Count + _nativeSegwitWallets.Count + _segwitWallets.Count;
            WriteToEventLog($">>> Count of wallets loaded: {wallets:N0}");
        }

        private ScriptPubKeyType[] CalculatePartitions()
        {
            List<ScriptPubKeyType> partitions = new();

            if (_legacyWallets.Count > 0)
            {
                partitions.Add(ScriptPubKeyType.Legacy);
            }

            if (_nativeSegwitWallets.Count > 0)
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

            while (!ct.IsCancellationRequested)
            {
                byte[] entropy = RandomGenerator.GetNextBytes(EntropyLength);

                Mnemonic mnemonic;
                BitcoinAddress address;
                Key key;

                for (int i = 0; i < ScanRange && !ct.IsCancellationRequested; i++)
				{
                    mnemonic = new Mnemonic(Wordlist.English, entropy);
                    key = mnemonic.DeriveExtKey().PrivateKey;

                    // Legacy
                    address = key.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
                    if (_legacyWallets.Contains(address.ToString()))
					{
                        SavePrivateKey(key, mnemonic, address);
                        WriteToEventLog($">>> Private key has been found! HEX: {key.ToHex()}");
					}

                    // Native Segwit
                    address = key.GetAddress(ScriptPubKeyType.Segwit, Network.Main);
                    if (_nativeSegwitWallets.Contains(address.ToString()))
                    {
                        SavePrivateKey(key, mnemonic, address);
                        WriteToEventLog($">>> Private key has been found! HEX: {key.ToHex()}");
                    }

                    // Segwit
                    address = key.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);
                    if (_segwitWallets.Contains(address.ToString()))
                    {
                        SavePrivateKey(key, mnemonic, address);
                        WriteToEventLog($">>> Private key has been found! HEX: {key.ToHex()}");
                    }

                    Interlocked.Increment(ref ProgressTracker);
                    entropy.Increment();
                }
            }
        }

        private void CreateCommonThreadsAndRun()
        {
            for (int iTask = 0; iTask < _tasks.Length; iTask++)
            {
                Task task = new Task(CommonRunner, TaskCreationOptions.LongRunning);
                _tasks[iTask] = task;
                task.Start();
            }
        }

        private void CreateThreadsEvenlyAndRun(IReadOnlyList<ScriptPubKeyType> partitions)
        {
            int threads = Environment.ProcessorCount / partitions.Count;

            for (int iTask = 0; iTask < _tasks.Length; iTask++)
            {
                Action action = ResolveThreadAction(partitions[iTask / threads]);
                Task task = new Task(action, TaskCreationOptions.LongRunning);
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
                ScriptPubKeyType.Segwit => NativeSegwitRunner,
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

        private void CreateComplexThreadsAndRun(IEnumerable<ScriptPubKeyType> partitions)
        {
            int wallets = _legacyWallets.Count + _nativeSegwitWallets.Count + _segwitWallets.Count;

            List<AddressType> addressTypes = partitions.Select(type => new AddressType
            {
                Type = type,
                Threads = Math.Clamp((int) Math.Floor(Environment.ProcessorCount * GetWalletsCount(type) / (double) wallets), 1, Environment.ProcessorCount)
            }).ToList();

            int remainder = Environment.ProcessorCount - addressTypes.Sum(x => x.Threads);
            while (remainder-- != 0)
            {
                HandleRemainderThreads(addressTypes);
            }

            int iType = 0;
            addressTypes.ForEach(at =>
            {
                for (int i = 0; i < at.Threads; i++)
                {
                    Task task = new Task(ResolveThreadAction(at.Type), TaskCreationOptions.LongRunning);
                    _tasks[iType + i] = task;
                    task.Start();
                }

                iType += at.Threads;
            });
        }

        private static void HandleRemainderThreads(IReadOnlyList<AddressType> addressTypes, int index = -1)
        {
            if (index != -1)
            {
                addressTypes[index].Threads++;
                return;
            }

            AddressType type = addressTypes.SingleOrDefault(x => x.Type == PriorityType);

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
                ScriptPubKeyType.Segwit => _nativeSegwitWallets.Count,
                ScriptPubKeyType.SegwitP2SH => _segwitWallets.Count,
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        private void LegacyRunner()
        {
            CancellationToken ct = _cts.Token;

            while (!ct.IsCancellationRequested)
            {
                byte[] entropy = RandomGenerator.GetNextBytes(EntropyLength);

                Mnemonic mnemonic;
                BitcoinAddress address;
                Key key;

                for (int i = 0; i < ScanRange && !ct.IsCancellationRequested; i++)
				{
                    mnemonic = new Mnemonic(Wordlist.English, entropy);
                    key = mnemonic.DeriveExtKey().PrivateKey;
                    address = key.GetAddress(ScriptPubKeyType.Legacy, Network.Main);

                    if (_legacyWallets.Contains(address.ToString()))
					{
                        SavePrivateKey(key, mnemonic, address);
                        WriteToEventLog($">>> Private key has been found! HEX: {key.ToHex()}");
					}

                    Interlocked.Increment(ref ProgressTracker);
                    entropy.Increment();
				}
            }
        }

        private void NativeSegwitRunner()
        {
            CancellationToken ct = _cts.Token;

            while (!ct.IsCancellationRequested)
            {
                byte[] entropy = RandomGenerator.GetNextBytes(EntropyLength);

                Mnemonic mnemonic;
                BitcoinAddress address;
                Key key;

                for (int i = 0; i < ScanRange && !ct.IsCancellationRequested; i++)
                {
                    mnemonic = new Mnemonic(Wordlist.English, entropy);
                    key = mnemonic.DeriveExtKey().PrivateKey;
                    address = key.GetAddress(ScriptPubKeyType.Segwit, Network.Main);

                    if (_nativeSegwitWallets.Contains(address.ToString()))
                    {
                        SavePrivateKey(key, mnemonic, address);
                        WriteToEventLog($">>> Private key has been found! HEX: {key.ToHex()}");
                    }

                    Interlocked.Increment(ref ProgressTracker);
                    entropy.Increment();
                }
            }
        }

        private void SegwitRunner()
        {
            CancellationToken ct = _cts.Token;

            while (!ct.IsCancellationRequested)
            {
                byte[] entropy = RandomGenerator.GetNextBytes(EntropyLength);

                Mnemonic mnemonic;
                BitcoinAddress address;
                Key key;

                for (int i = 0; i < ScanRange && !ct.IsCancellationRequested; i++)
                {
                    mnemonic = new Mnemonic(Wordlist.English, entropy);
                    key = mnemonic.DeriveExtKey().PrivateKey;
                    address = key.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main);

                    if (_segwitWallets.Contains(address.ToString()))
                    {
                        SavePrivateKey(key, mnemonic, address);
                        WriteToEventLog($">>> Private key has been found! HEX: {key.ToHex()}");
                    }

                    Interlocked.Increment(ref ProgressTracker);
                    entropy.Increment();
                }
            }
        }

        private static void SavePrivateKey(Key key, Mnemonic mnemonic, BitcoinAddress address)
        {
            lock (FileLock)
            {
                while (true)
                {
                    try
                    {
                        WriteKeyToFile(key, mnemonic, address);
                        break;
                    }
                    catch
                    {
                        // wait a bit until file is ready
                        Thread.Sleep(TimeSpan.FromSeconds(10));
                    }
                }
            }
        }

        private static void WriteKeyToFile(Key key, Mnemonic mnemonic, BitcoinAddress address)
        {
            using (StreamWriter file = File.AppendText(Path.Combine(AppContext.BaseDirectory, FoundFile)))
            {
                file.WriteLine($"Address: {address}");
                file.WriteLine($"Mnemonic: [{mnemonic}]");
                file.WriteLine("Private key:");
                   file.WriteLine($">>> HEX: {key.ToHex()}");
                   file.WriteLine($">>> WIF: {key.GetBitcoinSecret(Network.Main).ToWif()}");

                file.WriteLine();
                file.Flush();
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            Task[] execTasks = _tasks.Where(x => x != null).ToArray();
            if (execTasks.Length > 0)
			{
                Task.WaitAll(execTasks);
			}

            return base.StopAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested) 
            {
                await Task.Delay(NotifyPeriod, stoppingToken);

                GC.Collect();
                GC.WaitForPendingFinalizers();

                ulong keys = Interlocked.Read(ref ProgressTracker);
                WriteToEventLog($">>> Count of keys checked so far: {keys:N0}");
            }
        }

        private static void WriteToEventLog(string message)
        {
#if DEBUG
            return;
#endif
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            using (EventLog log = new EventLog("Application"))
            {
                log.Source = Program.ServiceName;
                log.WriteEntry(message, EventLogEntryType.Information);
            }
        }
    }
}