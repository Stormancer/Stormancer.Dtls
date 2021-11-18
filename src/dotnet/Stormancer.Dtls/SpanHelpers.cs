using System;
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
            if(buffer.Length < 3)
            {
                return 0;
            }

            buffer[0] = (byte)(value >> 16);
            buffer[1] = (byte)(value >> 8);
            buffer[2] = (byte)value;

            return 3;
        }

        
    }
}
