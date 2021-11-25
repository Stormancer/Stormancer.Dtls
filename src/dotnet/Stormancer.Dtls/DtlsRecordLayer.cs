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

        private Channel<Datagram> _sendChannel = Channel.CreateUnbounded<Datagram>();
        private Channel<Datagram> _receiveChannel = Channel.CreateUnbounded<Datagram>();

        private Dictionary<IPEndPoint, DtlsSession> _connections = new Dictionary<IPEndPoint, DtlsSession>();
        private object _connectionsSyncRoot = new object();

        public async Task<bool> ConnectAsync(IPEndPoint ipEndPoint, CancellationToken cancellationToken)
        {
            var connection = new DtlsSession(ipEndPoint, this);
            lock (_connectionsSyncRoot)
            {
                if (!_connections.TryAdd(ipEndPoint, connection))
                {
                    return false;
                }
            }

            try
            {
                return await connection.ConnectAsync(cancellationToken);
            }
            catch
            {
                lock (_connectionsSyncRoot)
                {
                    _connections.Remove(ipEndPoint);
                }
                throw;
            }

        }

        public ChannelReader<Datagram> SendReader => _sendChannel.Reader;
        public ChannelWriter<Datagram> ReceiveWriter => _receiveChannel.Writer;

        public DtlsRecordLayer()
        {

        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {

            await foreach (var datagram in _receiveChannel.Reader.ReadAllAsync(cancellationToken))
            {
                using (datagram)
                {
                    HandleDatagram(datagram);

                }
            }

        }

        internal Task SendHelloAsync()
        {
            throw new NotImplementedException();
        }


      
        private void HandleDatagram(Datagram datagram)
        {
            var dataLeft = true;
            var span = datagram.Data.Span;

            while (dataLeft)
            {

                var recordType = GetRecordType(span);
                int read = 0;
                switch (recordType)
                {
                    case DtlsRecordType.PlainText:
                        {
                            read = HandlePlainTextRecord(span, datagram.RemoteEndpoint);

                            break;
                        }
                    case DtlsRecordType.CipherText:
                        {
                            read = HandleCipherTextRecord(span, datagram.RemoteEndpoint);

                            break;
                        }
                    case DtlsRecordType.Invalid:
                        dataLeft = false;
                        break;
                }

                if (read > 0)
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
        private int HandlePlainTextRecord(in ReadOnlySpan<byte> span, IPEndPoint remoteEndpoint)
        {
            var read = DtlsPlainTextHeader.TryRead(span, out var recordHeader);

            if (read > 0)
            {
              
                var handshakeHeaderLength = DtlsHandshakeHeader.TryRead(span.Slice(read, recordHeader.Length), out var handshakeHeader);
                if (handshakeHeaderLength < 0)
                {
                    return -1;
                }

                read += handshakeHeaderLength;


                lock (_connectionsSyncRoot)
                {

                    if (!_connections.TryGetValue(remoteEndpoint, out var connection))
                    {
                        if (handshakeHeader.MsgType == HandshakeType.client_hello)
                        {
                            connection = new DtlsSession(remoteEndpoint, this);
                            _connections.Add(remoteEndpoint, connection);
                        }
                        else
                        {
                            return -1;
                        }
                    }

                    var recordContentSize = connection.TryHandlePlainTextRecord(recordHeader, handshakeHeader, span.Slice(read, recordHeader.Length - handshakeHeaderLength));
                    if(recordContentSize < 0)
                    {
                        return -1;
                    }

                    read += recordContentSize;
                }
                return read;
            }
            else
            {
                return -1;
            }
        }

        private int HandleCipherTextRecord(ReadOnlySpan<byte> span, IPEndPoint remoteEndpoint)
        {
            var read = DtlsUnifiedHeader.TryReadHeader(span, out var header);

            if (read != 0)
            {
                var content = span.Slice(read, header.Length);

                lock (_connectionsSyncRoot)
                {
                    if (_connections.TryGetValue(remoteEndpoint, out var connection))
                    {
                        connection.HandleCipherTextRecord(ref header, content);
                    }
                }

                return read + header.Length;
            }
            else
            {
                return 0;
            }
        }
        public void WritePlainTextMessage()
        {

        }
        public int TryWrite(Span<byte> buffer, in DtlsPlainTextHeader header)
        {
            return header.TryWrite(buffer);
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
