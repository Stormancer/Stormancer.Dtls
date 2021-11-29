using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Channels;
using Stormancer.Dtls.HandshakeMessages;

namespace Stormancer.Dtls
{
    public struct Datagram : IDisposable
    {
        private readonly IMemoryOwner<byte> owner;

        public Datagram(IMemoryOwner<byte> owner, ReadOnlyMemory<byte> data, IPEndPoint remoteEndpoint)
        {
            this.owner = owner;
            Data = data;
            RemoteEndpoint = remoteEndpoint;
        }

        public IPEndPoint RemoteEndpoint { get; }
        public ReadOnlyMemory<byte> Data { get; }

        public void Dispose()
        {
            owner.Dispose();
        }
    }
    internal class DtlsRecordLayer
    {


        private Sessions sessions;
        private readonly ChannelReader<Datagram> reader;
        private readonly ChannelWriter<Datagram> writer;

        private AckController ackController = new AckController();
        private AlertController alertController = new AlertController();
        private HandshakeController handshakeController = new HandshakeController();



        public DtlsRecordLayer(Sessions sessionManager, ChannelReader<Datagram> reader, ChannelWriter<Datagram> writer)
        {
            this.sessions = sessionManager;
            this.reader = reader;
            this.writer = writer;
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {

            await foreach (var datagram in reader.ReadAllAsync(cancellationToken))
            {
                using (datagram)
                {
                    HandleDatagram(datagram);

                }
            }

        }

        private void HandleDatagram(Datagram datagram)
        {
            var dataLeft = true;
            var span = datagram.Data.Span;

            while (dataLeft)
            {

                var recordType = GetRecordType(span);
                int read = 0;
                bool success = false;
                switch (recordType)
                {
                    case DtlsRecordType.PlainText:
                        {
                            success = TryHandlePlainTextRecord(span, datagram.RemoteEndpoint, out read);

                            break;
                        }
                    case DtlsRecordType.CipherText:
                        {
                            success = TryHandleCipherTextRecord(span, datagram.RemoteEndpoint, out read);

                            break;
                        }
                    case DtlsRecordType.Invalid:
                        dataLeft = false;
                        break;
                }

                if (success)
                {
                    span = span.Slice(read);
                    if (span.Length == 0)
                    {
                        dataLeft = false;
                    }

                }
                else //Failed to read record, ignore the rest of the datagram.
                {
                    dataLeft = false;
                }



            }


        }
        private bool TryHandlePlainTextRecord(ReadOnlySpan<byte> span, IPEndPoint remoteEndpoint, out int read)
        {
            read = 0;

            if (DtlsPlainTextHeader.TryRead(span, out var recordHeader, out var headerRead))
            {
                read += headerRead;
            }
            else
            {
                return false;
            }

            if (span.Length < read + recordHeader.Length)
            {
                return false;
            }
            DtlsSession? session;
            sessions.TryGetSession(remoteEndpoint, out session);


            if (DtlsRecordNumber.TryReconstructRecordNumber(recordHeader, session?.Epochs, out var recordNumber, out var epoch))
            {

                var success = true;
                while (read < span.Length && success)
                {
                    int recordRead = 0;
                    success = recordHeader.Type switch
                    {
                        ContentType.ChangeCipherSpec => false, // DTLS1.2
                        ContentType.Alert => alertController.TryHandleAlertRecord(session, recordNumber, epoch, span.Slice(read, recordHeader.Length), out recordRead),
                        ContentType.Handshake => handshakeController.TryHandleHandshakeRecord(remoteEndpoint, session,recordNumber,epoch,span.Slice(read,recordHeader.Length),out recordRead),
                        ContentType.ApplicationData => false, //DTLS1.2
                        ContentType.Heartbeat => false, //No plaintext heartbeat in DTLS1.3
                        ContentType.Tls12Cid => false, // DTL1.2 not supported,
                        ContentType.Ack => ackController.TryHandleAckRecord(session, recordNumber, epoch, span.Slice(read, recordHeader.Length), out recordRead),
                        _ => false
                    };
                    read += recordRead;

                }
                return success;
            }
            else
            {
                return false;
            }

        }

       

        private bool TryHandleCipherTextRecord(ReadOnlySpan<byte> span, IPEndPoint remoteEndpoint, out int read)
        {


            if (DtlsUnifiedHeader.TryReadHeader(span, out var header, out var headerLength))
            {
                var content = span.Slice(headerLength, header.Length);



                if (sessions.TryGetSession(remoteEndpoint, out var session))
                {

                    throw new NotImplementedException();
                }


                read = headerLength + header.Length;
                return true;
            }
            else
            {
                read = 0;
                return false;
            }
        }



        /// <summary>
        /// Get record header type.
        /// </summary>
        /// <remarks>
        /// https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-demultiplexing-dtls-records
        /// </remarks>
        /// <param name="buffer"></param>
        /// <returns></returns>
        private static DtlsRecordType GetRecordType(ReadOnlySpan<byte> buffer) =>
            buffer[0] switch
            {
                (byte)ContentType.Alert => DtlsRecordType.PlainText,
                (byte)ContentType.Handshake => DtlsRecordType.PlainText,
                (byte)ContentType.Ack => DtlsRecordType.PlainText,
                var hdr => (hdr & 0b_0010_0000) != 0 ? DtlsRecordType.CipherText : DtlsRecordType.Invalid
            };

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
