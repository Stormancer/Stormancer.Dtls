using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class Sessions
    {
        private Dictionary<System.Net.IPEndPoint, DtlsSession> _sessions = new Dictionary<System.Net.IPEndPoint, DtlsSession>();

        private object _sessionLock = new object();

        public bool TryGetSession(IPEndPoint endpoint,[NotNullWhen(true)] out DtlsSession? session)
        {
            lock(_sessionLock)
            {
                return _sessions.TryGetValue(endpoint, out session);
            }
        }
    }
}
