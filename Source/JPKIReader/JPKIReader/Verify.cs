using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;
using System.IO;

namespace JPKIReaderLib
{
    public class Verify
    {
        private static byte[] Read(System.IO.BinaryReader reader)
        {
            // tag
            reader.ReadByte();

            // length
            int length = 0;
            byte b = reader.ReadByte();
            if ((b & 0x80) == 0x80) // length が128 octet以上
            {
                int n = b & 0x7F;
                byte[] buf = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                for (var i = n - 1; i >= 0; --i)
                    buf[i] = reader.ReadByte();
                length = BitConverter.ToInt32(buf, 0);
            } else // length が 127 octet以下
            {
                length = b;
            }

            // value
            if (length == 0)
                return new byte[0];
            byte first = reader.ReadByte();
            if (first == 0x00) length -= 1; // 最上位byteが0x00の場合は、除いておく
            else reader.BaseStream.Seek(-1, SeekOrigin.Current); // 1byte 読んじゃったので、streamの位置を戻しておく
            return reader.ReadBytes(length);
        }

        private static RSAParameters CreateParameter(byte[] der)
        {
            byte[] sequence1 = null;
            using (var reader = new BinaryReader(new MemoryStream(der))) {
                sequence1 = Read(reader);
            }

            byte[] sequence2 = null;
            using (var reader = new BinaryReader(new MemoryStream(sequence1))) {
                Read(reader); // sequence
                sequence2 = Read(reader); // bit string
            }

            byte[] sequence3 = null;
            using (var reader = new BinaryReader(new MemoryStream(sequence2))) {
                sequence3 = Read(reader); // sequence
            }

            var parameters = new RSAParameters();
            using (var reader = new BinaryReader(new MemoryStream(sequence3))) {
                parameters.Modulus = Read(reader); // モジュラス
                parameters.Exponent = Read(reader); // 公開指数
            }

            return parameters;
        }

        private static bool verifySignature(byte[] publicKeyDER, byte[] signature, byte[] digestSHA1)
        {
            var parameters = CreateParameter(publicKeyDER);

            // verify
            var provider = new RSACryptoServiceProvider();
            provider.ImportParameters(parameters);

            return (provider.VerifyHash(digestSHA1, "SHA1", signature));
        }

        public static bool VerifySignature(byte[] publicKeyDER,byte[] signature,string targetFile)
        {
            byte[] digestSHA1 = null;
            using (var fs = new System.IO.FileStream(targetFile, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
                digestSHA1 = System.Security.Cryptography.SHA1.Create().ComputeHash(fs);
            }

            return(verifySignature(publicKeyDER, signature, digestSHA1));
        }

    }
}
