using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Sample
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var cts = new CancellationTokenSource();
            var token = cts.Token;

            var task = RunPeers(token);

            Console.Read();
            cts.Cancel();

            await Task.WhenAll(task);

        }

        private static async Task RunPeers(CancellationToken cancellationToken)
        {
            var client = new DtlsPeer();
            var server = new DtlsPeer();

            var t1 = client.RunAsync(cancellationToken);
            var t2 = server.RunAsync(cancellationToken);

            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, server.LocalPort),cancellationToken);

            await Task.WhenAll(t1, t2);
        }
    }
}
