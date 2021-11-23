using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{
    //    enum { warning(1), fatal(2), (255) } AlertLevel;
    //    enum {
    //        close_notify(0),
    //        unexpected_message(10),
    //        bad_record_mac(20),
    //        record_overflow(22),
    //        handshake_failure(40),
    //        bad_certificate(42),
    //        unsupported_certificate(43),
    //        certificate_revoked(44),
    //        certificate_expired(45),
    //        certificate_unknown(46),
    //        illegal_parameter(47),
    //        unknown_ca(48),
    //        access_denied(49),
    //        decode_error(50),
    //        decrypt_error(51),
    //        protocol_version(70),
    //        insufficient_security(71),
    //        internal_error(80),
    //        inappropriate_fallback(86),
    //        user_canceled(90),
    //        missing_extension(109),
    //        unsupported_extension(110),
    //        unrecognized_name(112),
    //        bad_certificate_status_response(113),
    //        unknown_psk_identity(115),
    //        certificate_required(116),
    //        no_application_protocol(120),
    //          (255)
    //      }
    //    AlertDescription;



    public enum AlertLevel
    {
        warning = 1, fatal = 2
    }
    public enum AlertDescription : byte
    {
        close_notify = 0,
        unexpected_message = 10,
        bad_record_mac = 20,
        record_overflow = 22,
        handshake_failure = 40,
        bad_certificate = 42,
        unsupported_certificate = 43,
        certificate_revoked = 44,
        certificate_expired = 45,
        certificate_unknown = 46,
        illegal_parameter = 47,
        unknown_ca = 48,
        access_denied = 49,
        decode_error = 50,
        decrypt_error = 51,
        protocol_version = 70,
        insufficient_security = 71,
        internal_error = 80,
        inappropriate_fallback = 86,
        user_canceled = 90,
        missing_extension = 109,
        unsupported_extension = 110,
        unrecognized_name = 112,
        bad_certificate_status_response = 113,
        unknown_psk_identity = 115,
        certificate_required = 116,
        no_application_protocol = 120
    }
    /// <summary>
    /// Alert message content
    /// </summary>
    /// <remarks>
    /// https://www.rfc-editor.org/rfc/rfc8446.html#section-6
    /// </remarks>
    internal readonly struct DtlsAlert
    {
        public DtlsAlert(AlertLevel alertLevel, AlertDescription alertDescription)
        {
            Level = alertLevel;
            Description = alertDescription;
        }

        //      struct {
        //          AlertLevel level;
        //    AlertDescription description;
        //}
        //Alert;

        public static int TryRead(ReadOnlySpan<byte> buffer, out DtlsAlert alert)
        {
            if(buffer.Length < 2)
            {
                alert = default;
                return -1;
            }

            alert = new DtlsAlert((AlertLevel)buffer[0], (AlertDescription)buffer[1]);
            return 2;
        }

        public int TryWrite(Span<byte> buffer)
        {
            if(buffer.Length < 2)
            {
                return -1;
            }

            buffer[0] = (byte)Level;
            buffer[1] = (byte)Description;
            return 2;
        }

        public static int GetLength()
        {
            return 2;
        }


        public AlertLevel Level { get; }
        public AlertDescription Description { get; }
    }
}
