using Stormancer.Dtls.HandshakeMessages;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class DtlsMessageBuffer
    {
        
        private Dictionary<IPEndPoint, MessageBuffer> _buffer = new Dictionary<IPEndPoint, MessageBuffer>();

        private object _syncRoot = new object();
        public bool TryGetCompleteOrAddPartial(IPEndPoint ipEndpoint, int fragmentOffset, int totalLength, ReadOnlySpan<byte> content)
        {
            bool mustAdd = false;
            MessageBuffer buffer;
            lock (_syncRoot)
            {
                
                if(!_buffer.TryGetValue(ipEndpoint, out buffer))
                {
                    mustAdd = true;
                    buffer = new MessageBuffer(totalLength);
                    
                }
            }

            if (fragmentOffset > buffer.Written)
            {
                return false;
            }
            content.CopyTo(buffer.Data.Span.Slice(fragmentOffset));
        }

        private struct MessageBuffer : IDisposable
        {
            private IMemoryOwner<byte> _owner;
            public MessageBuffer(int length)
            {
                Written = 0;

                _owner = MemoryPool<byte>.Shared.Rent(length);

            }
            /// <summary>
            /// Number of bytes written.
            /// </summary>
            public int Written { get; set; }

            public Memory<byte> Data => _owner.Memory;

            public void Dispose()
            {
                throw new NotImplementedException();
            }
        }
    }




}

   


}
