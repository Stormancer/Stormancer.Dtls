using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    internal class HeartbeatService
    {
        private readonly DtlsConnection connectionState;
        private readonly DtlsRecordLayer recordLayer;

        public HeartbeatService(DtlsConnection connectionState, DtlsRecordLayer recordLayer)
        {
            this.connectionState = connectionState;
            this.recordLayer = recordLayer;
        }

        /// <summary>
        /// Gets the currently calculated PMTU
        /// </summary>
        /// <remarks>
        /// The PMTU is regularly updated, 
        /// The PMTU can change
        /// </remarks>
        

        public async Task Start(CancellationToken cancellationToken)
        {
            var testMtu = 60;
            while (!cancellationToken.IsCancellationRequested)
            {

                
            }
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
