using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

/// <summary>
/// DTLS implementation
/// </summary>
/// <remarks>
/// <see href="https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html"/>
/// </remarks>
namespace Stormancer.Dtls
{
    public enum ContentType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
        Heartbeat = 24,
        Tls12Cid = 25,
        Ack = 26,
    }

    public enum DtlsRecordType
    {
        PlainText,
        CipherText,
        Invalid,
    }

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

        public static int TryRead(ReadOnlySpan<byte> buffer, out DtlsHandshakeHeader header)
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

    // 0 1 2 3 4 5 6 7
    //+-+-+-+-+-+-+-+-+
    //|0|0|1|C|S|L|E E|
    //+-+-+-+-+-+-+-+-+
    //| Connection ID |   Legend:
    //| (if any,      |
    ///  length as    /   C   - Connection ID(CID) present
    //|  negotiated)  |   S   - Sequence number length
    //+-+-+-+-+-+-+-+-+   L   - Length present
    //|  8 or 16 bit  |   E   - Epoch
    //|Sequence Number|
    //+-+-+-+-+-+-+-+-+
    //| 16 bit Length |
    //| (if present)  |
    //+-+-+-+-+-+-+-+-+
    public readonly struct DtlsUnifiedHeader
    {

        private byte HeaderStructure { get; }
        public bool ConnectionIdPresent => (HeaderStructure & 0b_0001_0000) != 0;
        public bool SequenceNumberLength => (HeaderStructure & 0b_0000_1000) != 0;

        public bool LengthPresent => (HeaderStructure & 0b_0000_0100) != 0;

        public byte Epoch => (byte)(HeaderStructure & 0b_0000_0011);

        public ushort SequenceNumber { get; }
        public ushort Length { get; }

        public DtlsUnifiedHeader(bool sequenceNumberLength, ushort sequenceNumber, bool lengthPresent, ushort length, ushort epoch)
        {
            HeaderStructure = 0b_0010_0000;

            if (sequenceNumberLength)
            {
                HeaderStructure |= 0b_0000_1000;

            }
            if (lengthPresent)
            {
                HeaderStructure |= 0b_0000_0100;
            }

            HeaderStructure |= (byte)(epoch & 0b_0000_0011);
            SequenceNumber = sequenceNumber;
            Length = length;
        }

        public static int TryReadHeader(ReadOnlySpan<byte> span, out DtlsUnifiedHeader header)
        {
            var headerStructure = span[0];
            var offset = 1;
            ushort sequenceNumber;
            var sequenceNumberLength = (headerStructure & 0b_0000_1000) != 0;
            if (sequenceNumberLength)
            {
                sequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset));
                offset += 2;
            }
            else
            {
                sequenceNumber = span[offset];
                offset += 1;
            }

            var lengthPresent = (headerStructure & 0b_0000_0100) != 0;
            ushort length;
            if (lengthPresent)
            {
                length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset));
                offset += 2;
            }
            else
            {
                length = 0;
            }

            ushort epoch = (ushort)(headerStructure & 0b_0000_0011);
            header = new DtlsUnifiedHeader(sequenceNumberLength, sequenceNumber, lengthPresent, length, epoch);
            return offset;
        }

        public int TryWriteHeader(Span<byte> span)
        {
            span[0] = HeaderStructure;
            int offset = 1;
            if (SequenceNumberLength)
            {
                BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset), SequenceNumber);
                offset += 2;
            }
            else
            {
                span[offset] = (byte)SequenceNumber;
                offset += 1;
            }

            if (LengthPresent)
            {
                BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset), Length);
                offset += 2;
            }
            return offset;
        }


    }
    public readonly struct DtlsPlainTextHeader
    {
        public DtlsPlainTextHeader(ContentType type, in DtlsPlainTextRecordNumber number, ushort length)
        {
            Type = type;
            Number = number;
            Length = length;
        }

        /// <summary>
        /// Tries reading the header from a span, and returns the number of bytes read.
        /// </summary>
        /// <param name="span"></param>
        /// <param name="header"></param>
        /// <returns></returns>
        public static int TryRead(ReadOnlySpan<byte> span, out DtlsPlainTextHeader header)
        {
            if (span.Length < 13)
            {
                header = default;
                return 0;
            }

            var type = (ContentType)span[0];
            Vector<byte> targetProtocolVersion = new Vector<byte>(ProtocolVersion);
            if (targetProtocolVersion != new Vector<byte>(span.Slice(1, 2)))
            {
                header = default;
                return 0;
            }
            var read = DtlsPlainTextRecordNumber.TryRead(span.Slice(3, 8), out var number);
            if (read == 0)
            {
                header = default;
                return 0;
            }

            var length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(read + 3, 2));

            header = new DtlsPlainTextHeader(type, number, length);
            return 13;
        }

        public ContentType Type { get; }
        public static byte[] ProtocolVersion { get; set; } = new byte[] { 254, 253 };

        public DtlsPlainTextRecordNumber Number { get; }

        public ushort Length { get; }


        public int TryWrite(Span<byte> span)
        {
            if (span.Length < 13)
            {
                return 0;
            }
            span[0] = (byte)Type;
            span[1] = ProtocolVersion[0];
            span[2] = ProtocolVersion[1];
            Number.TryWrite(span.Slice(3, 8));
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(11, 2), Length);

            return 13;
        }


    }



    public readonly struct DtlsPlainTextRecordNumber
    {
        public DtlsPlainTextRecordNumber(ushort epoch, ulong sequenceNumber)
        {
            Epoch = epoch;
            SequenceNumber = sequenceNumber;
        }

        public static int TryRead(ReadOnlySpan<byte> buffer, out DtlsPlainTextRecordNumber number)
        {
            if (buffer.Length < 8)
            {
                number = default;
                return 0;
            }
            var n = (buffer[0] & 0xff) << 8;
            n |= (buffer[1] & 0xff);
            var epoch = (ushort)n;

            uint hi = buffer.Slice(2).ReadUint24();
            uint lo = buffer.Slice(5).ReadUint24();
            var sequenceNumber = ((ulong)(hi & 0xffffffffL) << 24) | (ulong)(lo & 0xffffffffL);

            number = new DtlsPlainTextRecordNumber(epoch, sequenceNumber);
            return 8;
        }



        public int TryWrite(Span<byte> buffer)
        {
            if (buffer.Length < 8)
            {
                return 0;
            }
            var epoch = Epoch;
            var sequenceNumber = SequenceNumber;
            buffer[0] = (byte)(epoch >> 8);
            buffer[1] = (byte)epoch;
            buffer[2] = (byte)(sequenceNumber >> 40);
            buffer[3] = (byte)(sequenceNumber >> 32);
            buffer[4] = (byte)(sequenceNumber >> 24);
            buffer[5] = (byte)(sequenceNumber >> 16);
            buffer[6] = (byte)(sequenceNumber >> 8);
            buffer[7] = (byte)sequenceNumber;
            return 8;
        }
        /// <summary>
        /// The epoch changes on key renegotiation.
        /// </summary>
        public ushort Epoch { get; }

        /// <summary>
        /// 48 bit seq number.
        /// </summary>
        public ulong SequenceNumber { get; }
    }




    public class DtlsRecordLayer
    {
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


    }

    /// <summary>
    /// Contains data about a DTLS connection.
    /// </summary>
    public class DtlsConnectionState
    {
        internal DtlsConnectionState()
        {
            _epochs[0] = new EpochState(); 
        }

        public DtlsConnectionPhase Phase { get; set; } = DtlsConnectionPhase.Handshake;

        public EpochState CurrentEpoch
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
        private EpochState?[] _epochs = new EpochState?[EPOCH_STATE_BUFFER_LENGTH];
        private int _currentEpochIndex = 0;

        public IEnumerable<EpochState> Epochs
        {
            get
            {
                for(int i = _currentEpochIndex+EPOCH_STATE_BUFFER_LENGTH; i > _currentEpochIndex; i--)
                {
                    var epoch = _epochs[i % EPOCH_STATE_BUFFER_LENGTH];
                    if(epoch != null)
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

        private const int EPOCH_STATE_BUFFER_LENGTH = 8;
        /// <summary>
        /// Reconstructs the record number from <see cref="DtlsPlainTextHeader"/>
        /// </summary>
        /// <remarks>
        /// https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-reconstructing-the-sequence
        /// </remarks>
        /// <param name=""></param>
        /// <returns></returns>
        bool TryReconstructRecordNumber(DtlsPlainTextRecordNumber number, out DtlsRecordNumber output)
        {
            if ((ushort)CurrentEpoch.Epoch == number.Epoch)
            {
                output = new DtlsRecordNumber(CurrentEpoch.Epoch, number.SequenceNumber);
                return true;
            }
            else if (Phase == DtlsConnectionPhase.Active)
            {
                foreach (var epoch in Epochs)
                {
                    if ((ushort)epoch.Epoch == number.Epoch)
                    {
                        output = new DtlsRecordNumber(epoch.Epoch, number.SequenceNumber);
                        return true;
                    }
                }

                output = default;
                return false;

            }
            else
            {
                //We are in the handshake phase, the Epoch bits should unambiguously indicate the current epoch.
                output = default;
                return false;
            }
        }

        bool TryReconstructRecordNumber(DtlsUnifiedHeader header, out DtlsRecordNumber output)
        {
            if ((byte)CurrentEpoch.Epoch == header.Epoch)
            {
                ulong sequenceNumber = header.SequenceNumberLength ?
                    (CurrentEpoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffff0000) | header.SequenceNumber:
                     (CurrentEpoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffffff00) | header.SequenceNumber;
               
                output = new DtlsRecordNumber(CurrentEpoch.Epoch, sequenceNumber);
                return true;
            }
            else if (Phase == DtlsConnectionPhase.Active)
            {
                foreach (var epoch in Epochs)
                {
                    if ((byte)epoch.Epoch == header.Epoch)
                    {
                        ulong sequenceNumber = header.SequenceNumberLength ?
                            (epoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffff0000) | header.SequenceNumber :
                            (epoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffffff00) | header.SequenceNumber;

                        output = new DtlsRecordNumber(epoch.Epoch, sequenceNumber);
                        return true;
                    }
                }

                output = default;
                return false;

            }
            else
            {
                //We are in the handshake phase, the Epoch bits should unambiguously indicate the current epoch.
                output = default;
                return false;
            }
        }

        void Encrypt()
        {
            using(Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.ECB;
            }
        }
    }
    public readonly struct DtlsRecordNumber
    {
        public DtlsRecordNumber(ulong epoch, ulong sequenceNumber)
        {
            Epoch = epoch;
            SequenceNumber = sequenceNumber;
        }
        public ulong Epoch { get; }
        public ulong SequenceNumber { get; }
    }

    public enum DtlsConnectionPhase
    {
        Handshake,
        Active
    }
    public class EpochState
    {
        public DateTime StartedOn { get; } = DateTime.UtcNow;
        public ulong Epoch { get; set; } = 0;
        public ulong LatestDeprotectedSequenceNumber { get; set; } = 0;

        
    }
}