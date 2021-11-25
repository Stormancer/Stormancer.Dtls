using System;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Sample
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var array = new byte[2048];
            byte[] hash1, hash2;
            using (var sha = SHA256.Create())
            {

               

                hash1 = sha.ComputeHash(array);
            }

            using (var sha = SHA256.Create())
            {
           
                sha.TransformBlock(array, 0, 500, null, 0);
                sha.TransformBlock(array, 500, 1024, null, 0);
                //sha.TransformBlock(array, 1024, 512, null, 0);
                sha.TransformFinalBlock(array, 1524, 524);
                hash2 = sha.Hash;
            }
            //var cts = new CancellationTokenSource();
            //var token = cts.Token;

            //var task = RunPeers(token);

            //Console.Read();
            //cts.Cancel();

            //await Task.WhenAll(task);

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
