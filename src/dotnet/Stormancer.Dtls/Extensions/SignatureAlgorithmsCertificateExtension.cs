using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.Extensions
{
    internal class SignatureAlgorithmsCertificateExtension : IDtlsExtensionData
    {
        public DtlsExtensionType Type => DtlsExtensionType.signature_algorithms_cert;
    }
}
