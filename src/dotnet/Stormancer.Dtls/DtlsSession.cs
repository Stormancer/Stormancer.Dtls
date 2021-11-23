using Stormancer.Dtls.HandshakeMessages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    public class DtlsSessionConfiguration
    {
        public IEnumerable<ushort> CipherSuites { get; set; } = new ushort[] { DtlsCipherSuites.TLS_AES_128_GCM_SHA256 };
    }
    /// <summary>
    /// Contains data about a DTLS connection.
    /// </summary>
    public class DtlsSession
    {
        private const int EPOCH_STATE_BUFFER_LENGTH = 8;
        private readonly DtlsRecordLayer recordLayer;
        private readonly PacketLayer _packetLayer;
        private readonly DtlsHandshake _handshake;

        internal DtlsSession(System.Net.IPEndPoint ipEndPoint, DtlsRecordLayer recordLayer)
        {
            _packetLayer = new PacketLayer(this);
            _handshake = new DtlsHandshake(_packetLayer, this);

            _epochs[0] = new Epoch();
            RemoteEndpoint = ipEndPoint;
            this.recordLayer = recordLayer;
        }

        public DtlsSessionConfiguration SessionConfiguration { get; set; } = new DtlsSessionConfiguration();

        public DtlsConnectionPhase Phase { get; set; } = DtlsConnectionPhase.Handshake;
        public IPEndPoint RemoteEndpoint { get; }

        public int Pmtu { get; set; }
        public Epoch CurrentEpoch
        {
            get
            {

                var epoch = _epochs[_currentEpochIndex];
                Debug.Assert(epoch != null);
                return epoch;
            }
        }

        /// <summary>
        /// We keep the last 8 epochs to be able to decode older messages.
        /// </summary>
        private Epoch?[] _epochs = new Epoch?[EPOCH_STATE_BUFFER_LENGTH];
        private int _currentEpochIndex = 0;

        public IEnumerable<Epoch> Epochs
        {
            get
            {
                for (int i = _currentEpochIndex + EPOCH_STATE_BUFFER_LENGTH; i > _currentEpochIndex; i--)
                {
                    var epoch = _epochs[i % EPOCH_STATE_BUFFER_LENGTH];
                    if (epoch != null)
                    {
                        yield return epoch;
                    }
                    else
                    {
                        yield break;

                    }
                }
            }
        }

        /// <summary>
        /// Time the Session expires. 
        /// </summary>
        /// <remarks>
        /// The packet layer updates the expiration date each time a packet is sent or received.
        /// </remarks>
        public DateTime ExpirationDate => _packetLayer.ExpirationDate;

        public Task<bool> ConnectAsync(CancellationToken cancellationToken)
        {
            //Send an Hello request without cookies
            //Expect an HelloRetryRequest with a cookie.
            //await SendHelloAsync();

            return _handshake.PerformAsync(cancellationToken);
        }


        /// <summary>
        /// Reconstructs the record number from <see cref="DtlsPlainTextHeader"/>
        /// </summary>
        /// <remarks>
        /// https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-reconstructing-the-sequence
        /// </remarks>
        /// <param name=""></param>
        /// <returns></returns>
        bool TryReconstructRecordNumber(in DtlsPlainTextHeader header, out DtlsRecordNumber output, [NotNullWhen(true)] out Epoch? epoch)
        {
            var number = header.Number;
            if ((ushort)CurrentEpoch.EpochId == number.Epoch)
            {
                output = new DtlsRecordNumber(CurrentEpoch.EpochId, number.SequenceNumber);
                epoch = CurrentEpoch;
                return true;
            }
            else if (Phase == DtlsConnectionPhase.Active)
            {
                foreach (var e in Epochs)
                {
                    if ((ushort)e.EpochId == number.Epoch)
                    {
                        output = new DtlsRecordNumber(e.EpochId, number.SequenceNumber);
                        epoch = e;
                        return true;
                    }
                }

                output = default;
                epoch = default;
                return false;

            }
            else
            {
                //We are in the handshake phase, the Epoch bits should unambiguously indicate the current epoch.
                output = default;
                epoch = default;
                return false;
            }
        }

        bool TryReconstructRecordNumber(in DtlsUnifiedHeader header, out DtlsRecordNumber output, [NotNullWhen(true)] out Epoch? epoch)
        {
            if ((byte)CurrentEpoch.EpochId == header.Epoch)
            {
                ulong sequenceNumber = header.SequenceNumberLength ?
                    (CurrentEpoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffff0000) | header.SequenceNumber :
                     (CurrentEpoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffffff00) | header.SequenceNumber;

                output = new DtlsRecordNumber(CurrentEpoch.EpochId, sequenceNumber);
                epoch = CurrentEpoch;
                return true;
            }
            else if (Phase == DtlsConnectionPhase.Active)
            {
                foreach (var e in Epochs)
                {
                    if ((byte)e.EpochId == header.Epoch)
                    {
                        ulong sequenceNumber = header.SequenceNumberLength ?
                            (e.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffff0000) | header.SequenceNumber :
                            (e.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffffff00) | header.SequenceNumber;

                        output = new DtlsRecordNumber(e.EpochId, sequenceNumber);
                        epoch = e;
                        return true;
                    }
                }

                output = default;
                epoch = default;
                return false;

            }
            else
            {
                //We are in the handshake phase, the Epoch bits should unambiguously indicate the current epoch.
                output = default;
                epoch = default;
                return false;
            }
        }



        internal void HandleCipherTextRecord(ref DtlsUnifiedHeader header, ReadOnlySpan<byte> content)
        {
            if (TryReconstructRecordNumber(header, out var number, out var epoch))
            {

            }
        }

        internal int TryHandlePlainTextRecord(in DtlsPlainTextHeader header, in DtlsHandshakeHeader handshakeHeader, in ReadOnlySpan<byte> content)
        {
            if (TryReconstructRecordNumber(header, out var number, out var epoch))
            {

            }

            throw new NotImplementedException();
        }
    }
   
}
