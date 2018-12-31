using System;
using System.Collections.Generic;
using System.Linq;

namespace JPKIReaderLib
{
    public class Common
    {
        // 16進数文字列 => Byte配列
        public static byte[] HexStringToBytes(string str)
        {
            var bs = new List<byte>();
            for (int i = 0; i < str.Length / 2; i++) {
                bs.Add(Convert.ToByte(str.Substring(i * 2, 2), 16));
            }
            // "01-AB-EF" こういう"-"区切りを想定する場合は以下のようにする
            // var bs = str.Split('-').Select(hex => Convert.ToByte(hex, 16));
            return bs.ToArray();
        }

        // Byte配列 => 16進数文字列
        public static string BytesToHexString(byte[] bs)
        {
            var str = BitConverter.ToString(bs);
            // "-"がいらないなら消しておく
            str = str.Replace("-", string.Empty);
            return str;
        }

        public static int ToInt32(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 4);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt32(sub, 0);
        }

        public static int ToInt16(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 2);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt16(sub, 0);
        }

        // バイト配列から一部分を抜き出す
        private static byte[] GetSubArray(byte[] src, int startIndex, int count)
        {
            byte[] dst = new byte[count];
            Array.Copy(src, startIndex, dst, 0, count);
            return dst;
        }

        // ビットON/OFFをGET
        public static bool GetBit(byte bdata,int bit)
        {
            byte mask = 0x00;
            if( bit == 0) {
                mask = 0x01;
            } else if( bit == 1) {
                mask = 0x02;
            } else if (bit == 2) {
                mask = 0x04;
            } else if (bit == 3) {
                mask = 0x08;
            } else if (bit == 4) {
                mask = 0x10;
            } else if (bit == 5) {
                mask = 0x20;
            } else if (bit == 6) {
                mask = 0x40;
            } else if (bit == 7) {
                mask = 0x80;
            }
            if ((bdata & mask) == mask) {
                return true;
            } else {
                return false;
            }
        }

        // DERをPEMに変換する(CERTIFICATE)
        public static string ConvertCertificateDERtoPEM(byte[] certificateDER)
        {
            // DER形式の証明書をPEM形式に変換する
            //     DER -> 鍵や証明書をASN.1というデータ構造で表し、それをシリアライズしたバイナリファイル
            //     PEM -> DERと同じASN.1のバイナリデータをBase64によってテキスト化されたファイル 
            // 1.Base64エンコード
            // 2.64文字ごとに改行コードをいれる
            // 3.ヘッダとフッタを入れる

            var b64cert = Convert.ToBase64String(certificateDER);

            string pemdata = "";
            int roopcount = (int)Math.Ceiling(b64cert.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pemdata = pemdata + b64cert.Substring(start) + "\n";
                } else {
                    pemdata = pemdata + b64cert.Substring(start, 64) + "\n";
                }
            }
            pemdata = string.Format("-----BEGIN CERTIFICATE-----\n") + pemdata + string.Format("-----END CERTIFICATE-----\n");

            return pemdata;
        }

        // バイナリデータをHEX文字列に変換、スペースと改行で適当に加工してファイルに出力する
        public static bool ExportHextoFile(string path,byte[] source)
        {
            try {
                var hexstr = JPKIReaderLib.Common.BytesToHexString(source);
                int insertcount = 1;
                for (int i = 2; i < hexstr.Length; i += 3) {
                    if (insertcount % 16 == 0) {
                        hexstr = hexstr.Insert(i, "\n");
                    } else {
                        hexstr = hexstr.Insert(i, " ");
                    }
                    insertcount++;
                }
                System.IO.File.WriteAllText(path, hexstr);

            } catch (Exception) {

            }
            return (true);
        }

    }
}

