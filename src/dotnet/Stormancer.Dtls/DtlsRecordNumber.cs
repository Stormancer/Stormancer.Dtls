using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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


        /// <summary>
        /// Reconstructs the record number from <see cref="DtlsPlainTextHeader"/>
        /// </summary>
        /// <remarks>
        /// https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-reconstructing-the-sequence
        /// </remarks>
        /// <param name=""></param>
        /// <param name="epochs">list of epochs from latest to oldest</param>
        /// <returns></returns>
        public static bool TryReconstructRecordNumber(in DtlsPlainTextHeader header, IEnumerable<Epoch>? epochs, out DtlsRecordNumber output, out Epoch? epoch)
        {
           
            var plainTextHeaderNumber = header.Number.SequenceNumber;
            var plainTextHeaderEpoch = header.Number.Epoch;
            
            if (epochs == null)// No session yet established. this mean we are in the stateless ClientHello phase. Epoch must
            {
                if (plainTextHeaderEpoch == 0 && plainTextHeaderNumber ==0)
                {
                    epoch = null;
                    output = new DtlsRecordNumber(0, plainTextHeaderNumber);
                    return true;
                }
                else
                {
                    epoch = default;
                    output = default;
                    return false;
                }
            }
            var currentEpoch = epochs.First();
            if ((ushort)currentEpoch.EpochId == plainTextHeaderEpoch)
            {
                output = new DtlsRecordNumber(currentEpoch.EpochId, plainTextHeaderNumber);
                epoch = currentEpoch;
                return true;
            }
            else
            {
                foreach (var e in epochs)
                {
                    if ((ushort)e.EpochId == plainTextHeaderEpoch)
                    {
                        output = new DtlsRecordNumber(e.EpochId, plainTextHeaderNumber);
                        epoch = e;
                        return true;
                    }
                }

                output = default;
                epoch = default;
                return false;

            }
        }

        public static bool TryReconstructRecordNumber(in DtlsUnifiedHeader header, IEnumerable<Epoch>? epochs, out DtlsRecordNumber output, [NotNullWhen(true)] out Epoch? epoch)
        {
            if(epochs == null)
            {
                epoch = default;
                output= default;
                return false;
            }

            var currentEpoch = epochs.First();
            ulong sequenceNumber = header.SequenceNumberLength ?
                    (currentEpoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffff0000) | header.SequenceNumber :
                     (currentEpoch.LatestDeprotectedSequenceNumber & 0x_ffffffff_ffffff00) | header.SequenceNumber;
            var epochNb = header.Epoch;

            if ((byte)currentEpoch.EpochId == epochNb)
            {
                

                output = new DtlsRecordNumber(currentEpoch.EpochId, sequenceNumber);
                epoch = currentEpoch;
                return true;
            }
            else
            {
                foreach (var e in epochs)
                {
                    if ((byte)e.EpochId == header.Epoch)
                    {
                        output = new DtlsRecordNumber(e.EpochId, sequenceNumber);
                        epoch = e;
                        return true;
                    }
                }

                output = default;
                epoch = default;
                return false;

            }
           
        }
    }
}
