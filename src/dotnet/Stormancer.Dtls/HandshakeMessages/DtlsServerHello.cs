﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.HandshakeMessages
{
    /// <summary>
    /// ServerHello and HelloRetryRequest message structure.
    /// </summary>
    /// <remarks>
    /// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3
    /// </remarks>
    /// <param name="cipherSuite"></param>
    /// <param name="isHelloRetryRequest"></param>
    //The server will send this message in response to a ClientHello
    //message to proceed with the handshake if it is able to negotiate an
    //acceptable set of handshake parameters based on the ClientHello.

    //Structure of this message:

    //   struct {
    //       ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    //     Random random;
    //     opaque legacy_session_id_echo<0..32>;
    //     CipherSuite cipher_suite;
    //     uint8 legacy_compression_method = 0;
    //     Extension extensions<6..2^16-1>;
    // }
    // ServerHello;

    //legacy_version:  In previous versions of TLS, this field was used for
    //   version negotiation and represented the selected version number
    //   for the connection.  Unfortunately, some middleboxes fail when
    //   presented with new values.In TLS 1.3, the TLS server indicates
    //   its version using the "supported_versions" extension
    //   (Section 4.2.1), and the legacy_version field MUST be set to
    //   0x0303, which is the version number for TLS 1.2.  (See Appendix D
    //   for details about backward compatibility.)

    //random:  32 bytes generated by a secure random number generator.See
    //   Appendix C for additional information.  The last 8 bytes MUST be
    //   overwritten as described below if negotiating TLS 1.2 or TLS 1.1,
    //   but the remaining bytes MUST be random.This structure is
    //   generated by the server and MUST be generated independently of the
    //   ClientHello.random.

    //legacy_session_id_echo:  The contents of the client's
    //   legacy_session_id field.  Note that this field is echoed even if
    //   the client's value corresponded to a cached pre-TLS 1.3 session
    //   which the server has chosen not to resume.  A client which
    //   receives a legacy_session_id_echo field that does not match what
    //   it sent in the ClientHello MUST abort the handshake with an
    //   "illegal_parameter" alert.

    //cipher_suite:  The single cipher suite selected by the server from
    //   the list in ClientHello.cipher_suites.A client which receives a
    //   cipher suite that was not offered MUST abort the handshake with an
    //   "illegal_parameter" alert.

    //legacy_compression_method:  A single byte which MUST have the
    //   value 0.
    internal readonly ref struct DtlsServerHello
    {
       

        public DtlsServerHello(ushort cipherSuite, bool isHelloRetryRequest = false)
        {

            CipherSuite = cipherSuite;

            if (!isHelloRetryRequest)
            {
                using var generator = RandomNumberGenerator.Create();
                var bytes = new byte[32];
                generator.GetBytes(bytes);
                Random = new ReadOnlyMemory<byte>(bytes);
            }
            else
            {
                Random = HelloRetryRequestId;
            }
        }

        public static ushort LegacyVersion { get; } = 0xFEFD;

        public ReadOnlyMemory<byte> Random { get; }

        public static byte LegacySessionIdEcho { get; } = 0;

        public ushort CipherSuite { get; }

        public static byte LegacyCompressionMethod { get; } = 0;



        private static ReadOnlyMemory<byte> HelloRetryRequestId => new ReadOnlyMemory<byte>(new byte[] {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2 , 0xA2 , 0x11 , 0x16 , 0x7A , 0xBB , 0x8C , 0x5E , 0x07 , 0x9E , 0x09 , 0xE2 , 0xC8 , 0xA8 , 0x33 , 0x9C});

        /// <summary>
        /// Determines if the message is an hello retry request
        /// </summary>
        /// <remarks>
        /// For reasons of backward compatibility with middleboxes (see
        /// Appendix D.4), the HelloRetryRequest message uses the same structure
        ///as the ServerHello, but with Random set to the special value of the
        ///SHA-256 of "HelloRetryRequest":

        ///  CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
        ///  C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
        /// </remarks>
        public bool IsHelloRetryRequest() => new Vector<byte>(HelloRetryRequestId.Span) == new Vector<byte>(Random.Span);


    }
}