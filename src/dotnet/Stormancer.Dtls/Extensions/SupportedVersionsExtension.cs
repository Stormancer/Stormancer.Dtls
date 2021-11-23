using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Extensions
{
    internal class SupportedVersionsExtension : IDtlsExtensionData
    {
        public DtlsExtensionType Type =>  DtlsExtensionType.supported_versions;
    }
}
