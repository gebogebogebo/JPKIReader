using System.Collections.Generic;
using System.Linq;

namespace JPKIReaderLib
{
    public partial class JPKIReader : ICReader
    {
        private static byte[] createDigestInfo(byte[] sigBaseSHA1)
        {
            // [ RFC 3447.PKCS #1.RSASSA-PKCS1-v1_5 ]

            // ASN.1 DigestInfo
            //DigestInfo::= SEQUENCE {
            //  SEQUENCE {
            //    OBJECT IDENTIFIER / SHA1(1,3,14,3,2,26)
            //    NULL
            //  }
            //  OCTET STRING digest
            //}

            // SEQUENCE
            var sequence = new List<byte>();
            // 01    : TAG             = SEQUENCE= 0x30             
            // 02    : Length of Value = length(OBJECT IDENTIFIER+NULL)             
            // 03-   : Value           = OBJECT IDENTIFIER+NULL
            {
                // <OBJECT IDENTIFIER>
                // 01    : TAG             = OID(OBJECT IDENTIFIER) = 0x06             
                // 02    : Length of Value = 5byte = 0x05             
                // 03-07 : Value           = 1,3,14,3,2,26 -> SHA1 = 0x2b 0e 03 02 1a 
                // http://www.geocities.co.jp/SiliconValley-SanJose/3377/asn1Body.html
                byte[] oid = new byte[] { 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a };

                // <NULL>
                // 01    : TAG             = NULL     = 0x05             
                // 02    : Length of Value = no Value = 0x00
                byte[] nl = new byte[] { 0x05, 0x00 };

                sequence.Add(0x30);
                sequence.Add((byte)(oid.Length + nl.Length));
                sequence.AddRange(oid.ToArray());
                sequence.AddRange(nl.ToArray());
            }

            // <OCTET STRING>
            // 01    : TAG             = OCTET STRING   = 0x04             
            // 02    : Length of Value = length(digest)
            // 03-   : Value           = digest
            var digest = new List<byte>();
            {
                digest.Add(0x04);
                digest.Add((byte)sigBaseSHA1.Length);
                digest.AddRange(sigBaseSHA1.ToArray());
            }

            // <DigestInfo>
            // 01    : TAG             = SEQUENCE= 0x30
            // 02    : Length of Value = length(SEQUENCE+digest)           
            // 03-   : Value           = SEQUENCE+digest
            var digestInfo = new List<byte>();
            {
                digestInfo.Add(0x30);
                digestInfo.Add((byte)(sequence.Count + digest.Count));
                digestInfo.AddRange(sequence);
                digestInfo.AddRange(digest);
            }

            return digestInfo.ToArray();
        }
    }
}
