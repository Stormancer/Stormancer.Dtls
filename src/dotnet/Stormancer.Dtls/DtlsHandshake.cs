using Stormancer.Dtls.Extensions;
using Stormancer.Dtls.HandshakeMessages;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    public enum DtlsHandshakePhase
    {
        None = 0,
        client_hello = 1,

        finished,

    }
    /// <summary>
    /// Implements the DtlsHandshake state machine of a connection.
    /// </summary>
    internal class DtlsHandshake
    {
        private readonly PacketLayer packetLayer;
        private readonly DtlsSession session;


        public DtlsHandshakePhase Phase { get; private set; }
        public DtlsHandshake(PacketLayer packetLayer, DtlsSession session)
        {
            this.packetLayer = packetLayer;
            this.session = session;
        }


        internal async Task<bool> PerformAsync(CancellationToken cancellationToken)
        {
            var serverHello = await SendInitialHelloAsync(cancellationToken);

            if (!serverHello.IsHelloRetryRequest())
            {
                return false;
            }


            return true;
        }



        private async Task<DtlsServerHello> SendInitialHelloAsync(CancellationToken cancellationToken)
        {
            var config = session.SessionConfiguration;


            var clientHelloMsg = new DtlsClientHello(config.CipherSuites, new IDtlsExtensionData[] {
                new SupportedVersionsExtension(),
                new SignatureAlgorithmsExtension(),
                new NegotiatedGroupsExtension(),
                new KeyshareExtension(),
            });

            var t = WaitServerHelloAsync(cancellationToken);
            await packetLayer.SendFlightAsync(clientHelloMsg, cancellationToken);

            return await t;
        }


        private bool TryProcessServerHello(in DtlsHandshakeHeader header, in ReadOnlySpan<byte> buffer)
        {
            if (_waitServerHelloTcs == null)//If unexpected, we ignore the message.
            {
                return false;
            }

            throw new NotImplementedException();
        }

        private async Task<DtlsServerHello> WaitServerHelloAsync(CancellationToken cancellationToken)
        {
            if(_waitServerHelloTcs !=null)
            {
                throw new InvalidOperationException("AlreadyWaiting");
            }
            try
            {
                _waitServerHelloTcs = new TaskCompletionSource<DtlsServerHello>();
                return await _waitServerHelloTcs.Task.WaitAsync(cancellationToken);
            }
            finally
            {
                _waitServerHelloTcs = null;
            }
        }
        private TaskCompletionSource<DtlsServerHello>? _waitServerHelloTcs;


        public bool TryProcessHandshake(in DtlsHandshakeHeader header, in ReadOnlySpan<byte> buffer)
        {
            return header.MsgType switch
            {

                HandshakeType.client_hello => DtlsClientHello.TryProcess(header, buffer),
                HandshakeType.server_hello => TryProcessServerHello(header, buffer),

                HandshakeType.new_session_ticket => throw new NotImplementedException(),
                HandshakeType.end_of_early_data => throw new NotImplementedException(),

                HandshakeType.encrypted_extensions => throw new NotImplementedException(),
                HandshakeType.certificate => throw new NotImplementedException(),

                HandshakeType.certificate_request => throw new NotImplementedException(),

                HandshakeType.certificate_verify => throw new NotImplementedException(),

                HandshakeType.finished => throw new NotImplementedException(),

                HandshakeType.key_update => throw new NotImplementedException(),
                HandshakeType.message_hash => throw new NotImplementedException(),
                _ => false
            };
        }
    }
}
