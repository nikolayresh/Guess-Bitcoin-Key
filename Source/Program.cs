using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GuessBitcoinKey
{
	public class Program
    {
		public const string ServiceName = "Guess Bitcoin Key";

        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
            .UseWindowsService(options =>
            {
                options.ServiceName = ServiceName;
            }).ConfigureServices((_, services) =>
                {
                    services.AddHostedService<Worker>();
                });
    }
}