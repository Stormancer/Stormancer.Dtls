using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal static class SpanHelpers
    {
        public static bool TryReadUint24(in ReadOnlySpan<byte> buf, out uint value, out int read)
        {
            if(buf.Length<3)
            {
                value = 0;
                read = 0;
                return false;
            }
            int n = (buf[0] & 0xff) << 16;
            n |= (buf[1] & 0xff) << 8;
            n |= (buf[2] & 0xff);
            value = (uint)n;
            read = 3;
            return true;
        }

        public static bool TryWriteUint24(in Span<byte> buffer, uint value, out int written)
        {
            if (buffer.Length < 3)
            {
                written = 0;
                return false;
            }

            buffer[0] = (byte)(value >> 16);
            buffer[1] = (byte)(value >> 8);
            buffer[2] = (byte)value;

            written = 3;
            return true;
           
        }

        public static bool TryReadUint48(this ReadOnlySpan<byte> buffer, out ulong value, out int read)
        {
            if (buffer.Length < 6)
            {
                value = default;
                read = 0;
                return false;
            }
            if (TryReadUint24(buffer, out var hi, out var r1) && TryReadUint24(buffer.Slice(3), out var lo, out var r2))
            {
                read = r1 + r2;
                value = ((ulong)(hi & 0xffffffffL) << 24) | (ulong)(lo & 0xffffffffL);
                return true;
            }
            else
            {
                value = default;
                read = default;
                return false;
            }

        }

        public static bool TryWriteUint48(in Span<byte> buffer, ulong value, out int written)
        {
            if (buffer.Length < 6)
            {
                written = default;
                return false;
            }
            buffer[0] = (byte)(value >> 40);
            buffer[1] = (byte)(value >> 32);
            buffer[2] = (byte)(value >> 24);
            buffer[3] = (byte)(value >> 16);
            buffer[4] = (byte)(value >> 8);
            buffer[5] = (byte)(value);
            written = 6;
            return true;

        }


    }
}
