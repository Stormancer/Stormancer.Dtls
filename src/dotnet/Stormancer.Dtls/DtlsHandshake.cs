using Stormancer.Dtls.Extensions;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    /// <summary>
    /// Implements the DtlsHandshake state machine of a connection.
    /// </summary>
    internal class DtlsHandshake
    {
        private readonly PacketLayer packetLayer;
        private readonly DtlsSession session;

        public DtlsHandshake(PacketLayer packetLayer, DtlsSession session)
        {
            this.packetLayer = packetLayer;
            this.session = session;
        }



        internal Task<bool> PerformAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }


        private void SendHello()
        {
            var config = session.SessionConfiguration;


            var clientHelloMsg = new DtlsClientHello(config.CipherSuites, new IDtlsExtensionData[] { 
                new SupportedVersionsExtension(), 
                new SignatureAlgorithmsExtension(),
                new NegotiatedGroupsExtension(),
                new KeyshareExtension(),

            });

            var memPool = MemoryPool<byte>.Shared;
            using var buffer = memPool.Rent(clientHelloMsg.GetLength());
            var span = buffer.Memory.Span;
            var written = clientHelloMsg.Write(ref span);
          
            packetLayer.SendFlight(span.Slice(0,written));
          
        }
    }
}
