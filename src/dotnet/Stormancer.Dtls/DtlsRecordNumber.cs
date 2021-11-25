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
        public static bool TryRead(ReadOnlySpan<byte> buffer, ref DtlsRecordNumber recordNumber,out int bytesRead)
        {
            if(!BinaryPrimitives.TryReadUInt64BigEndian(buffer, out var epoch))
            {
              
                bytesRead = 0;
                return false;
            }

            if (!BinaryPrimitives.TryReadUInt64BigEndian(buffer.Slice(8),out var sequenceNumber))
            {
               
                bytesRead = 0;
                return false;
            }

            recordNumber = new DtlsRecordNumber(epoch,sequenceNumber);
            bytesRead = 16;
            return true; 
        }

        public bool TryWrite(Span<byte> buffer, out int bytesWritten)
        {
            if (!BinaryPrimitives.TryWriteUInt64BigEndian(buffer, Epoch))
            {
                bytesWritten = 0;
                return false;
            }

            if(!BinaryPrimitives.TryWriteUInt64BigEndian(buffer.Slice(8),SequenceNumber))
            {
                bytesWritten = 0;
                return false;
            }
            bytesWritten = 16;
            return true;
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
