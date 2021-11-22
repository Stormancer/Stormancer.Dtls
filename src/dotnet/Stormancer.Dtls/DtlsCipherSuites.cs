using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    /// <summary>
    /// DTLS cipher suites
    /// </summary>
    /// <remarks>
    /// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    /// </remarks>
    public class DtlsCipherSuites
    {
        public const ushort TLS_AES_128_GCM_SHA256 = 0x1301;
        public const ushort TLS_AES_256_GCM_SHA384 = 0x1302;
        public const ushort TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
        public const ushort TLS_AES_128_CCM_SHA256 = 0x1304;
        public const ushort TLS_AES_128_CCM_8_SHA256 = 0x1305;

    }
}
