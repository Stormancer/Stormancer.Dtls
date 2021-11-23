using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Extensions
{
    internal readonly struct KeyshareExtension : IDtlsExtensionData
    {
        public DtlsExtensionType Type => DtlsExtensionType.key_share;
    }
}
