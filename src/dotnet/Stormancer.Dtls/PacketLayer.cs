using Stormancer.Dtls.HandshakeMessages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class PacketLayer
    {
        private readonly DtlsSession session;

        public PacketLayer(DtlsSession session)
        {
            this.session = session;
        }

        public DateTime ExpirationDate { get; internal set; }

        internal void SendFlight(in DtlsClientHello clientHelloMsg)
        {
            clientHelloMsg.GetLength();
            
        }

        internal Task SendFlightAsync(DtlsClientHello clientHelloMsg, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        internal Task SendFlightAsync(DtlsServerHello serverHello, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        internal Task SendFlightAsync(DtlsServerHello serverHello, )
    }
}
