using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    public class DtlsPeer : IDisposable
    {
        System.Net.Sockets.Socket _udpSocket;
        private DtlsRecordLayer _dtlsRecordLayer;
        private MemoryPool<byte> _memoryPool;
        public DtlsPeer(MemoryPool<byte>? memPool = null)
        {
           
            _udpSocket = new System.Net.Sockets.Socket( System.Net.Sockets.AddressFamily.InterNetworkV6, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
            
            _udpSocket.Bind(new IPEndPoint(IPAddress.Any,0));
            _udpSocket.Listen();

            _dtlsRecordLayer = new DtlsRecordLayer();
            
            if(memPool == null)
            {
                memPool = MemoryPool<byte>.Shared;
            }
            _memoryPool = memPool;
        }

        public Task<bool> ConnectAsync(IPEndPoint ipEndPoint, CancellationToken cancellationToken)
        {
            return _dtlsRecordLayer.ConnectAsync(ipEndPoint, cancellationToken);
        }

        public ushort LocalPort { get; }

        
        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                await Task.WhenAll(
                    _dtlsRecordLayer.RunAsync(cancellationToken),
                    RunReceiver(cancellationToken),
                    RunSender(cancellationToken)
                    );

            }
            finally
            {
                _dtlsRecordLayer.ReceiveWriter.Complete();
            }
        }

        private async Task RunReceiver(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var ipEndpoint = new IPEndPoint(IPAddress.Any, 0);
                var bufferOwner = _memoryPool.Rent();
                var result = await _udpSocket.ReceiveMessageFromAsync(bufferOwner.Memory, System.Net.Sockets.SocketFlags.None, ipEndpoint);
                if(result.ReceivedBytes > 0)
                {
                    
                    var datagram = new Datagram(bufferOwner, bufferOwner.Memory.Slice(0, result.ReceivedBytes), (IPEndPoint)result.RemoteEndPoint);

                    await _dtlsRecordLayer.ReceiveWriter.WriteAsync(datagram, cancellationToken);
                }
              
            }
        }

        private async Task RunSender(CancellationToken cancellationToken)
        {
            await foreach (var datagram in _dtlsRecordLayer.SendReader.ReadAllAsync(cancellationToken))
            {
                await _udpSocket.SendToAsync(datagram.Data, System.Net.Sockets.SocketFlags.None, datagram.RemoteEndpoint, cancellationToken);
            }
        }
        public void Dispose()
        {
            _dtlsRecordLayer.Dispose();
        }
    }

}
