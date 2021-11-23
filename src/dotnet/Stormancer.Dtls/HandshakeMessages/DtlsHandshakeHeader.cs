using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.HandshakeMessages
{
    public enum HandshakeType : byte
    {
        hello_request_RESERVED = 0,
        client_hello = 1,
        server_hello = 2,
        hello_verify_request_RESERVED = 3,
        new_session_ticket = 4,
        end_of_early_data = 5,
        hello_retry_request_RESERVED = 6,
        encrypted_extensions = 8,
        certificate = 11,
        server_key_exchange_RESERVED = 12,
        certificate_request = 13,
        server_hello_done_RESERVED = 14,
        certificate_verify = 15,
        client_key_exchange_RESERVED = 16,
        finished = 20,
        certificate_url_RESERVED = 21,
        certificate_status_RESERVED = 22,
        supplemental_data_RESERVED = 23,
        key_update = 24,
        message_hash = 254,

    }
    /// <summary>
    /// Handshake header
    /// </summary>
    /// <remarks>
    /// struct {
    ///    HandshakeType msg_type;    /* handshake type */
    ///    uint24 length;             /* bytes in message */
    ///    uint16 message_seq;        /* DTLS-required field */
    ///    uint24 fragment_offset;    /* DTLS-required field */
    ///    uint24 fragment_length;    /* DTLS-required field */
    ///    select(msg_type)
    ///    {
    ///        case client_hello: ClientHello;
    ///        case server_hello: ServerHello;
    ///        case end_of_early_data: EndOfEarlyData;
    ///        case encrypted_extensions: EncryptedExtensions;
    ///        case certificate_request: CertificateRequest;
    ///        case certificate: Certificate;
    ///        case certificate_verify: CertificateVerify;
    ///        case finished: Finished;
    ///        case new_session_ticket: NewSessionTicket;
    ///        case key_update: KeyUpdate;
    ///    }
    ///    body;
    ///
    ///}Handshake;
    /// 
    /// </remarks>
    public readonly struct DtlsHandshakeHeader
    {
        public DtlsHandshakeHeader(HandshakeType msgType, uint length, ushort messageSequence, uint fragmenOffset, uint fragmentLength)
        {
            this.MsgType = msgType;
            this.Length = length;
            this.MessageSequence = messageSequence;
            FragmentOffset = fragmenOffset;
            FragmentLength = fragmentLength;
        }
        public HandshakeType MsgType { get; }
        public uint Length { get; }
        public ushort MessageSequence { get; }
        public uint FragmentOffset { get; }
        public uint FragmentLength { get; }

        public static int TryRead(in ReadOnlySpan<byte> buffer, out DtlsHandshakeHeader header)
        {
            if (buffer.Length < 12)
            {
                header = default;
                return 0;
            }
            var msgType = (HandshakeType)buffer[0];
            var length = buffer.Slice(1).ReadUint24();
            var messageSequence = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(4));
            var fragmentOffset = buffer.Slice(6).ReadUint24();
            var fragmentLength = buffer.Slice(9).ReadUint24();

            header = new DtlsHandshakeHeader(msgType, length, messageSequence, fragmentOffset, fragmentLength);
            return 12;
        }

        public int TryWrite(Span<byte> buffer)
        {
            if (buffer.Length < 12)
            {
                return 0;
            }

            buffer[0] = (byte)MsgType;
            buffer.Slice(1).TryWriteUint24(Length);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(4), MessageSequence);
            buffer.Slice(6).TryWriteUint24(FragmentOffset);
            buffer.Slice(9).TryWriteUint24(FragmentLength);
            return 12;
        }


    }

}
