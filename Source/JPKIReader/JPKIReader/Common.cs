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
            if( bs == null) {
                return ("");
            }

            var str = BitConverter.ToString(bs);
            // "-"がいらないなら消しておく
            str = str.Replace("-", string.Empty);
            return str;
        }

        // DERをPEMに変換する(CERTIFICATE)
        public static string ConvertCertificateDERtoPEM(byte[] der)
        {
            // DER形式の証明書をPEM形式に変換する
            //     DER -> 鍵や証明書をASN.1というデータ構造で表し、それをシリアライズしたバイナリファイル
            //     PEM -> DERと同じASN.1のバイナリデータをBase64によってテキスト化されたファイル 
            // 1.Base64エンコード
            // 2.64文字ごとに改行コードをいれる
            // 3.ヘッダとフッタを入れる

            var b64 = Convert.ToBase64String(der);

            string pem = "";
            int roopcount = (int)Math.Ceiling(b64.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pem = pem + b64.Substring(start) + "\n";
                } else {
                    pem = pem + b64.Substring(start, 64) + "\n";
                }
            }
            pem = string.Format("-----BEGIN CERTIFICATE-----\n") + pem + string.Format("-----END CERTIFICATE-----\n");

            return pem;
        }

        // DERをPEMに変換する(PUBLIC KEY)
        public static string ConvertPublicKeyDERtoPEM(byte[] der)
        {
            var b64 = Convert.ToBase64String(der);

            string pem = "";
            int roopcount = (int)Math.Ceiling(b64.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pem = pem + b64.Substring(start) + "\n";
                } else {
                    pem = pem + b64.Substring(start, 64) + "\n";
                }
            }
            pem = string.Format("-----BEGIN PUBLIC KEY-----\n") + pem + string.Format("-----END PUBLIC KEY-----\n");
            return pem;
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

