using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    public class PmtuDiscovery
    {

        public static async Task<int> DiscoverMtu(IPAddress ipAddress)
        {
            var ping = new Ping();

            var reply = await ping.SendPingAsync(ipAddress, 1000, new byte[10], new PingOptions() { DontFragment = true});


            return 0;
        }


        //public Task<uint> DiscoverPathMTU(IPEndPoint endpoint)
        //{
        //    var properties = netInterface.GetIPProperties();

        //    uint mtu;

        //    if ((endpoint.AddressFamily & System.Net.Sockets.AddressFamily.InterNetwork) != 0)
        //    {
        //        mtu = (uint)properties.GetIPv4Properties().Mtu;
        //    }
        //    else
        //    {
        //        mtu = (uint)properties.GetIPv6Properties().Mtu;
        //    }

        //    var socket = new Socket(SocketType.Dgram, ProtocolType.Udp);

        //}
    }
}
