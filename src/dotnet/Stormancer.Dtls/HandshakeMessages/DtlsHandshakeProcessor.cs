using Stormancer.Dtls.Extensions;
using Stormancer.Dtls.HandshakeMessages;
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
