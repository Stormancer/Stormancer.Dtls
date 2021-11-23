using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Extensions
{
    public interface IDtlsExtensionHandler
    {
        DtlsExtensionType Type { get; }

        bool TryReadExtensionData(ReadOnlySpan<byte> readOnlySpan, out IDtlsExtensionData extension);


        int GetLength();

        int TryWrite(IDtlsExtensionData data, Span<byte> buffer);

    }
}
