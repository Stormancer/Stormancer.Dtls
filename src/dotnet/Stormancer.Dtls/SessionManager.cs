using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class SessionManager
    {
        private Dictionary<IPEndPoint, DtlsSession> _connections = new Dictionary<IPEndPoint, DtlsSession>();
        private object _connectionsSyncRoot = new object();
    }
}
