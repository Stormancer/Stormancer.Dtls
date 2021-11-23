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
        public static uint ReadUint24(this ReadOnlySpan<byte> buf)
        {
            int n = (buf[0] & 0xff) << 16;
            n |= (buf[1] & 0xff) << 8;
            n |= (buf[2] & 0xff);
            return (uint)n;
        }

        public static int TryWriteUint24(this Span<byte> buffer, uint value)
        {
            if (buffer.Length < 3)
            {
                return 0;
            }

            buffer[0] = (byte)(value >> 16);
            buffer[1] = (byte)(value >> 8);
            buffer[2] = (byte)value;

            return 3;
        }

        public static int TryReadUint48(this ReadOnlySpan<byte> buffer, out ulong value)
        {
            if (buffer.Length < 6)
            {
                value = default;
                return -1;
            }
            uint hi = buffer.ReadUint24();
            uint lo = buffer.Slice(3).ReadUint24();
            value = ((ulong)(hi & 0xffffffffL) << 24) | (ulong)(lo & 0xffffffffL);
            return 6;
        }

        public static int TryWriteUint48(this Span<byte> buffer, ulong value)
        {
            if (buffer.Length < 6)
            {
                return -1;
            }
            buffer[0] = (byte)(value >> 40);
            buffer[1] = (byte)(value >> 32);
            buffer[2] = (byte)(value >> 24);
            buffer[3] = (byte)(value >> 16);
            buffer[4] = (byte)(value >> 8);
            buffer[5] = (byte)(value);
            return 6;

        }


    }
}
