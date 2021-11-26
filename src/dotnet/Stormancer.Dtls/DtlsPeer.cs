using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    public class DtlsPeer : IDisposable
    {
        
        private DtlsRecordLayer _dtlsRecordLayer;
        private MemoryPool<byte> _memoryPool;
        public DtlsPeer(MemoryPool<byte>? memPool = null)
        {
           
           

            _dtlsRecordLayer = new DtlsRecordLayer();
            
            if(memPool == null)
            {
                memPool = MemoryPool<byte>.Shared;
            }
            _memoryPool = memPool;
        }

        public Task<bool> ConnectAsync(IPEndPoint ipEndPoint, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public ushort LocalPort { get; }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                await Task.WhenAll(
                    _dtlsRecordLayer.RunAsync(cancellationToken),
                    RunReceiver(cancellationToken),
                    RunSender(cancellationToken)
                    );

            }
            finally
            {
                _dtlsRecordLayer.ReceiveWriter.Complete();
            }
        }

        public void Dispose()
        {
            _dtlsRecordLayer.Dispose();
        }
    }

}
