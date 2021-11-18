using System;
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
        System.Net.Sockets.Socket _udpSocket;
        System.Net.Sockets.Socket? _icmpSocket;
        public DtlsPeer()
        {
            var ping = new Ping();
           
          
            _udpSocket = new System.Net.Sockets.Socket( System.Net.Sockets.AddressFamily.InterNetworkV6, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
            _udpSocket.SetSocketOption(System.Net.Sockets.SocketOptionLevel.IPv6, System.Net.Sockets.SocketOptionName.IPv6Only, false);
            _udpSocket.SetSocketOption(System.Net.Sockets.SocketOptionLevel.Socket, System.Net.Sockets.SocketOptionName.ReuseAddress, true);

            
            
        }
        

        public void Start()
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }

}
