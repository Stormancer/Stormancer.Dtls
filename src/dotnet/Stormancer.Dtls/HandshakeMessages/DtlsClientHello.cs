using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls.HandshakeMessages
{
    


    /// <summary>
    /// ClientHello DTLS message
    /// </summary>
    /// <remarks>
    /// DTLS 1.3: https://tlswg.org/dtls13-spec/draft-ietf-tls-dtls13.html#name-clienthello-message
    /// TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2
    /// </remarks>
    //    uint16 ProtocolVersion;
    //    opaque Random[32];

    //    uint8 CipherSuite[2];    /* Cryptographic suite selector */

    //    struct {
    //        ProtocolVersion legacy_version = { 254, 253 }; // DTLSv1.2
    //    Random random;
    //    opaque legacy_session_id<0..32>;
    //    opaque legacy_cookie<0..2^8-1>;                  // DTLS
    //    CipherSuite cipher_suites<2..2^16-2>;
    //    opaque legacy_compression_methods<1..2^8-1>;
    //    Extension extensions<8..2^16-1>;
    //}
    //ClientHello;
    internal readonly struct DtlsClientHello 
    {
        public static bool TryReadFrom(in ReadOnlySpan<byte> buffer,out DtlsClientHello hello, out IReadOnlyDictionary<DtlsExtensionType, IDtlsExtensionData> extensions)
        {
            throw new NotImplementedException();
        }

        public static bool TryProcess(in DtlsHandshakeHeader header,in ReadOnlySpan<byte> buffer)
        {
            throw new NotImplementedException();
        }


        public int GetLength()
        {

            throw new NotImplementedException();
        }

        public int Write(ref Span<byte> buffer)
        {
            Debug.Assert(buffer.Length >= GetLength());

            return 0;
        }
        public DtlsClientHello(IEnumerable<ushort> cipherSuites, IEnumerable<IDtlsExtensionData> extensionData)
        {
           
            CipherSuites = cipherSuites;

            using var generator = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            generator.GetBytes(bytes);
            Random = new ReadOnlyMemory<byte>(bytes);
            Extensions = extensionData;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        /// In previous versions of DTLS, this field was used for version negotiation and represented the highest 
        /// version number supported by the client. Experience has shown that many servers do not properly implement 
        /// version negotiation, leading to "version intolerance" in which the server rejects an otherwise 
        /// acceptable ClientHello with a version number higher than it supports. In DTLS 1.3, the client indicates
        /// its version preferences in the "supported_versions" extension (see Section 4.2.1 of [TLS13]) and the 
        /// legacy_version field MUST be set to {254, 253}, which was the version number for DTLS 1.2. The 
        /// supported_versions entries for DTLS 1.0 and DTLS 1.2 are 0xfeff and 0xfefd (to match the wire versions).
        /// The value 0xfefc is used to indicate DTLS 1.3.
        /// </remarks>
        public static ushort Legacy_version { get; } = 0xFEFD;

        ///<summary>
        ///</summary>
        /// <remarks>
        /// DTLS 1.3:
        /// Same as for TLS 1.3, except that the downgrade sentinels described in Section 4.1.3 of [TLS13] when TLS 1.2
        /// and TLS 1.1 and below are negotiated apply to DTLS 1.2 and DTLS 1.0 respectively.
        /// </remarks>
        public ReadOnlyMemory<byte> Random { get; }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        /// DTLS 1.3:
        /// Versions of TLS and DTLS before version 1.3 supported a "session resumption" feature which has been merged
        /// with pre-shared keys in version 1.3. A client which has a cached session ID set by a pre-DTLS 1.3 server 
        /// SHOULD set this field to that value. Otherwise, it MUST be set as a zero-length vector (i.e., a zero-valued
        /// single byte length field).
        /// TODO: Support DTLS 1.2
        /// </remarks>
        public static byte Legacy_Session { get; } = 0;

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        /// A DTLS 1.3-only client MUST set the legacy_cookie field to zero length. If a DTLS 1.3 ClientHello is received 
        /// with any other value in this field, the server MUST abort the handshake with an "illegal_parameter" alert.
        /// </remarks>
        public static ReadOnlyMemory<byte> Legacy_Cookie { get; } = ReadOnlyMemory<byte>.Empty;

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        ///  A list of the symmetric cipher options supported by
        ///    the client, specifically the record protection algorithm
        ///    (including secret key length) and a hash to be used with HKDF, in
        ///  descending order of client preference.Values are defined in
        ///  Appendix B.4.  If the list contains cipher suites that the server
        ///  does not recognize, support, or wish to use, the server MUST
        ///  ignore those cipher suites and process the remaining ones as
        ///  usual.If the client is attempting a PSK key establishment, it
        ///SHOULD advertise at least one cipher suite indicating a Hash
        ///associated with the PSK.
        /// </remarks>
        public IEnumerable<ushort> CipherSuites { get; }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        /// Versions of TLS before 1.3 supported compression with the list 
        /// of supported compression methods being
        ///sent in this field.For every TLS 1.3 ClientHello, this vector
        ///MUST contain exactly one byte, set to zero, which corresponds to
        ///the "null" compression method in prior versions of TLS.If a
        ///TLS 1.3 ClientHello is received with any other value in this
        ///field, the server MUST abort the handshake with an
        ///"illegal_parameter" alert.Note that TLS 1.3 servers might
        ///receive TLS 1.2 or prior ClientHellos which contain other
        ///compression methods and (if negotiating such a prior version) MUST
        ///follow the procedures for the appropriate prior version of TLS.
        /// </remarks>
        public static byte Legacy_Compression_Methods { get; } = 0;

        public IEnumerable<IDtlsExtensionData> Extensions { get; } 

    }
}
