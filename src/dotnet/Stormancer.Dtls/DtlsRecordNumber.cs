using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    //    struct {
    //    uint64 epoch;
    //    uint48 sequence_number;
    //}
    //RecordNumber;
    public readonly struct DtlsRecordNumber
    {
        public static int TryRead(ReadOnlySpan<byte> buffer, ref DtlsRecordNumber recordNumber)
        {
            if(!BinaryPrimitives.TryReadUInt64BigEndian(buffer, out var epoch))
            {
                recordNumber = default;
                return -1;
            }

            if (buffer.Slice(8).TryReadUint48(out var sequenceNumber) != 6)
            {
                recordNumber = default;
                return -1;
            }

            recordNumber = new DtlsRecordNumber(epoch,sequenceNumber);
            return 14;
        }

        public int TryWrite(Span<byte> buffer)
        {
            if (!BinaryPrimitives.TryWriteUInt64BigEndian(buffer, Epoch))
            {
                return -1;
            }

            if(buffer.Slice(8).TryWriteUint48(SequenceNumber) != 6)
            {
                return -1;
            }
            return 14;
        }
        public static int GetLength()
        {
            return 14;
        }

        public DtlsRecordNumber(ulong epoch, ulong sequenceNumber)
        {
            Epoch = epoch;
            SequenceNumber = sequenceNumber;
        }
        public ulong Epoch { get; }
        public ulong SequenceNumber { get; }
    }
}
