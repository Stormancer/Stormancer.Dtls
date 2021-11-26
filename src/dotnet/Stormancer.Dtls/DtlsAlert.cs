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

        public static bool TryRead(ReadOnlySpan<byte> buffer, out DtlsAlert alert, out int read)
        {
            if(buffer.Length < 2)
            {
                alert = default;
                read = default;
                return false;
            }

            alert = new DtlsAlert((AlertLevel)buffer[0], (AlertDescription)buffer[1]);
            read = 2;
            return true;
        }

        public bool TryWrite(Span<byte> buffer, out int written)
        {
            if(buffer.Length < 2)
            {
                written = default;
                return false;
            }

            buffer[0] = (byte)Level;
            buffer[1] = (byte)Description;
            written = 2;
            return true;
        }

        public static int GetLength()
        {
            return 2;
        }


        public AlertLevel Level { get; }
        public AlertDescription Description { get; }
    }

    internal class AlertController
    {
        public bool TryHandleAlertRecord(DtlsSession? session, DtlsRecordNumber recordNumber, Epoch? epoch, ReadOnlySpan<byte> buffer, out int read)
        {
            if(epoch == null || session == null)
            {
                read = default;
                return false;
            }

            if(DtlsAlert.TryRead(buffer, out var alert, out var contentRead ))
            {
                read = contentRead;

                session.OnAlertReceived(alert);

                return true;
            }
            else
            {
                read = default;
                return false;
            }




        }
    }
}
