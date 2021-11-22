using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Extensions
{
    public interface IDtlsExtensionHandler
    {
        bool TryReadExtensionData(ReadOnlySpan<byte> readOnlySpan, out IDtlsExtensionData extension);
    }
}
