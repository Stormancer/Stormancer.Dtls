using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class DtlsConstants
    {
        public const int MAX_FRAGMENT_LENGTH = 1 << 14; //16kb
        public const int MAX_HANDSHAKE_MSG_LENGTH = 1 << 16; //64kb
    }
}
