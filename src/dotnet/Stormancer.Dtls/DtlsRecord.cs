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

        public static bool TryReadHeader(ReadOnlySpan<byte> span, out DtlsUnifiedHeader header, out int read)
        {
            if (span.Length < 2)
            {
                read = 0;
                header = default;
                return false;
            }

            var headerStructure = span[0];
            var offset = 1;
            ushort sequenceNumber;
            var sequenceNumberLength = (headerStructure & 0b_0000_1000) != 0;
            var lengthPresent = (headerStructure & 0b_0000_0100) != 0;



            if (sequenceNumberLength)
            {

                if (span.Length < 3)
                {
                    read = 0;
                    header = default;
                    return false;
                }

                sequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset));
                offset += 2;

            }
            else
            {
                sequenceNumber = span[offset];
                offset += 1;
            }


            ushort length;
            if (lengthPresent)
            {
                if (span.Length < offset + 2)
                {
                    read = 0;
                    header = default;
                    return false;
                }
                length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset));
                offset += 2;
            }
            else
            {
                length = 0;
            }

            ushort epoch = (ushort)(headerStructure & 0b_0000_0011);
            header = new DtlsUnifiedHeader(sequenceNumberLength, sequenceNumber, lengthPresent, length, epoch);
            read = offset;
            return true;
        }

        public bool TryWriteHeader(Span<byte> span, out int written)
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
            written = offset;
            return true;
        }


    }

    // struct {
    //    ContentType type;
    //    ProtocolVersion legacy_record_version;
    //    uint16 epoch = 0
    //        uint48 sequence_number;
    //    uint16 length;
    //    opaque fragment[DTLSPlaintext.length];
    //}
    //DTLSPlaintext;
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
        public static bool TryRead(in ReadOnlySpan<byte> span, out DtlsPlainTextHeader header, out int read)
        {
            if (span.Length < 13)
            {
                header = default;
                read = 0;
                return false;
            }

            var type = (ContentType)span[0];
            Vector<byte> targetProtocolVersion = new Vector<byte>(ProtocolVersion);
            if (targetProtocolVersion != new Vector<byte>(span.Slice(1, 2)))
            {
                header = default;
                read = 0;
                return false;
            }
            
            if (!DtlsPlainTextRecordNumber.TryRead(span.Slice(3, 8), out var number, out var bytesRead))
            {
                header = default;
                read = 0;
                return false;
            }
            
            var length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(bytesRead + 3, 2));

            header = new DtlsPlainTextHeader(type, number, length);
            read = 13;
            return true;
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
            Number.TryWrite(span.Slice(3, 8), out int written);

            Debug.Assert(written + 5 == 13);

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

        public static bool TryRead(ReadOnlySpan<byte> buffer, out DtlsPlainTextRecordNumber number, out int read)
        {
            if (buffer.Length < 8)
            {
                number = default;
                read = 0;
                return false;
            }
            var epoch = BinaryPrimitives.ReadUInt16BigEndian(buffer);

            if (!SpanHelpers.TryReadUint48(buffer,out var sequenceNumber, out _))
            {
                number = default;
                read = 0;
                return false;
            }

            number = new DtlsPlainTextRecordNumber(epoch, sequenceNumber);
            read = 8;
            return true;
        }



        public bool TryWrite(Span<byte> buffer,out int written)
        {
            if (buffer.Length < 8)
            {
                written = 0;
                return false;
            }
            var epoch = Epoch;
            var sequenceNumber = SequenceNumber;

            if (!BinaryPrimitives.TryWriteUInt16BigEndian(buffer, epoch))
            {
                written = 0;
                return false;
            }

            if (SpanHelpers.TryWriteUint48(buffer.Slice(2), sequenceNumber, out _))
            {
                written = 0;
                return false;
            }
            written = 8;
            return true;
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








    public enum DtlsConnectionPhase
    {
        Handshake,
        Active
    }
    public class Epoch
    {
        public DateTime StartedOn { get; } = DateTime.UtcNow;
        public ulong EpochId { get; set; } = 0;
        public ulong LatestDeprotectedSequenceNumber { get; set; } = 0;

        public int NumberOfAuthFailedPackets { get; set; } = 0;


    }
}