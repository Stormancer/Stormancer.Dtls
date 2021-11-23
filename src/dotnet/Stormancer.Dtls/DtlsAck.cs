using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.HandshakeMessages
{
    internal readonly struct DtlsAck
    {
        public DtlsAck(IEnumerable<DtlsRecordNumber> recordNumber)
        {
            RecordNumbers = recordNumber;
        }

        public static int TryRead(ReadOnlySpan<byte> buffer, out DtlsAck ack)
        {
            if (!BinaryPrimitives.TryReadUInt16BigEndian(buffer, out var length))
            {
                ack = default;
                return -1;
            }

            var recordNumbers = new DtlsRecordNumber[length / 14];
            var read = 2;

            buffer = buffer.Slice(2, length);
            for (int i = 0; i < recordNumbers.Length; i++)
            {
                var numberLength = DtlsRecordNumber.TryRead(buffer, ref recordNumbers[i]);
                if (numberLength < 0)
                {
                    ack = default;
                    return -1;
                }
                read += numberLength;

            }
            ack = new DtlsAck(recordNumbers);
            return read;

        }

        public int TryWrite(Span<byte> buffer)
        {
            if (buffer.Length < GetLength())
            {
                return -1;
            }
            var length = RecordNumbers.Count() * DtlsRecordNumber.GetLength();
            
            if (length  > ushort.MaxValue) //length must fit in ushort.
            {
                return -2;
            }
            
            BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)(length));

            return length + 2;
        }

        public int GetLength()
        {
            return 2 + RecordNumbers.Count() * DtlsRecordNumber.GetLength();
        }
        public IEnumerable<DtlsRecordNumber> RecordNumbers { get; }
    }
}
