using System;
using System.Net;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Sample
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await PmtuDiscovery.DiscoverMtu(IPAddress.Parse("8.8.8.8"));
            var p1 = new DtlsPeer();


            p1.Start();

            var p2 = new DtlsPeer();
            Console.WriteLine("Hello World!");
        }
    }
}
