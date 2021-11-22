using Stormancer.Dtls.Extensions;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Stormancer.Dtls
{


   
    public class DtlsHandshakeProcessor
    {
        public static bool TryProcess(in DtlsHandshakeHeader header,in ReadOnlySpan<byte> buffer)
        {
            return header.MsgType switch
            {

                HandshakeType.client_hello => DtlsClientHello.TryProcess(header, buffer),
                HandshakeType.server_hello => throw new NotImplementedException(),

                HandshakeType.new_session_ticket => throw new NotImplementedException(),
                HandshakeType.end_of_early_data => throw new NotImplementedException(),

                HandshakeType.encrypted_extensions => throw new NotImplementedException(),
                HandshakeType.certificate => throw new NotImplementedException(),

                HandshakeType.certificate_request => throw new NotImplementedException(),

                HandshakeType.certificate_verify => throw new NotImplementedException(),

                HandshakeType.finished => throw new NotImplementedException(),

                HandshakeType.key_update => throw new NotImplementedException(),
                HandshakeType.message_hash => throw new NotImplementedException(),
                _ => false
            };
        }

        private static readonly Dictionary<DtlsExtensionType, IDtlsExtensionData> EMPTY_DICTIONARY = new Dictionary<DtlsExtensionType, IDtlsExtensionData>();

        public static int TryReadExtensions(in ReadOnlySpan<byte> buffer, IDictionary<DtlsExtensionType,IDtlsExtensionHandler> extensionHandlers, [NotNullWhen(true)]out IReadOnlyDictionary<DtlsExtensionType, IDtlsExtensionData>? extensions)
        {

            if(!BinaryPrimitives.TryReadUInt16BigEndian(buffer, out var length))
            {
                extensions = default;
                return -1;
            }
            
            var read = 2;
            if(length!= 0)
            {
                var result = new Dictionary<DtlsExtensionType, IDtlsExtensionData>(8);
                while(buffer.Length > 0)
                {
                    if(!BinaryPrimitives.TryReadUInt16BigEndian(buffer.Slice(read), out var extensionTypeNb))
                    {
                        extensions = default;
                        return -1;
                    }

                  
                    read += 2;
                    if(!BinaryPrimitives.TryReadUInt16BigEndian(buffer.Slice(read), out var extensionLength))
                    {
                        extensions = default;
                        return -1;
                    }
                    
                    read += 2;

                    var extensionType = (DtlsExtensionType)extensionTypeNb;
                    
                    if(extensionHandlers.TryGetValue(extensionType,out var handler))
                    {
                     
                        if(handler.TryReadExtensionData(buffer.Slice(read, extensionLength), out var extension))
                        {
                            if (!result.TryAdd(extensionType, extension))
                            {
                                extensions = default;
                                return -1;
                            }
                        }
                        else 
                        {
                            extensions = default;
                            return -1;
                        }
                         
                    }
                    

                  
                    read += extensionLength;

                }
                extensions = result;
                return read;
            }
            else
            {
                extensions = EMPTY_DICTIONARY;
                return 2; 
            }



        }

    }
}
