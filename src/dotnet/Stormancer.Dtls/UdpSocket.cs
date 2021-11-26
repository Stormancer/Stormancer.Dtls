using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class UdpSocket
    {
        private readonly MemoryPool<byte> _memoryPool;
        private readonly ChannelReader<Datagram> reader;
        private readonly ChannelWriter<Datagram> writer;
        private readonly System.Net.Sockets.Socket _udpSocket;
        
        public UdpSocket(MemoryPool<byte> memoryPool, ChannelReader<Datagram> reader, ChannelWriter<Datagram> writer)
        {
            _memoryPool = memoryPool;
            this.reader = reader;
            this.writer = writer;
            _udpSocket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetworkV6, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
            _udpSocket.SetSocketOption(System.Net.Sockets.SocketOptionLevel.Socket, System.Net.Sockets.SocketOptionName.ReuseAddress, true);
            _udpSocket.Bind(new IPEndPoint(IPAddress.Any, 0));

        }

        public int Port
        {
            get
            {
                Debug.Assert(_udpSocket.LocalEndPoint != null);
                return ((IPEndPoint)_udpSocket.LocalEndPoint).Port;
            }
        }
        public Task RunAsync(CancellationToken cancellationToken)
        {
            return Task.WhenAll(RunReceiver(cancellationToken), RunSender(cancellationToken));
        }

        private async Task RunReceiver(CancellationToken cancellationToken)
        {
            _udpSocket.Listen();
            while (!cancellationToken.IsCancellationRequested)
            {
                var ipEndpoint = new IPEndPoint(IPAddress.Any, 0);
                var bufferOwner = _memoryPool.Rent();
                var result = await _udpSocket.ReceiveMessageFromAsync(bufferOwner.Memory, System.Net.Sockets.SocketFlags.None, ipEndpoint);
                if (result.ReceivedBytes > 0)
                {

                    var datagram = new Datagram(bufferOwner, bufferOwner.Memory.Slice(0, result.ReceivedBytes), (IPEndPoint)result.RemoteEndPoint);

                    await writer.WriteAsync(datagram, cancellationToken);
                }

            }
        }

        private async Task RunSender(CancellationToken cancellationToken)
        {
            await foreach (var datagram in reader.ReadAllAsync(cancellationToken))
            {
                await _udpSocket.SendToAsync(datagram.Data, System.Net.Sockets.SocketFlags.None, datagram.RemoteEndpoint, cancellationToken);
            }
        }
    }
}
