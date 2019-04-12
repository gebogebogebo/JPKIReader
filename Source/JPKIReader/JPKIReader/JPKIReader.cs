using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace JPKIReaderLib
{
    public partial class JPKIReader : ICReader
    {
        private static readonly byte[] APDU_SELECT_AP = { 0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01 };

        private static readonly byte[] APDU_SELECT_CERT_SIG = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x01 };
        private static readonly byte[] APDU_SELECT_CERT_SIGCA = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x02 };
        private static readonly byte[] APDU_SELECT_KEY_SIG = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1A };
        private static readonly byte[] APDU_SELECT_PIN_SIG = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1B };

        private static readonly byte[] APDU_SELECT_CERT_AUTH = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0A };
        private static readonly byte[] APDU_SELECT_CERT_AUTHCA = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0B };
        private static readonly byte[] APDU_SELECT_KEY_AUTH = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x17 };
        private static readonly byte[] APDU_SELECT_PIN_AUTH = { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x18 };


        private static byte[] readCert(ICReader reader)
        {
            var certDER = new List<byte>();

            // READ BINARY
            int datasize = 0;
            {
                // http://www.geocities.co.jp/SiliconValley-SanJose/3377/asn1Body.html
                // ブロックの最初の4byteを読む
                // ⇒30:82:06:2B
                // 30 = タグ
                //  ‭0011-0000
                //  00          b8-b7:クラス        00   = 汎用
                //    1         b6   :構造化フラグ  1    = 構造型
                //     1-0000   b5-b1:タグ番号      0x10 = SEQUENCE(ASN.1 オブジェクトの集合を表記するための型)

                // 82 = 値の長さ1(レングス)
                //  ‭1000-0010
                //‬  1           b8   :              1    = 128オクテット(byte)以上
                //   000-0010   b7-b1:              0x02 = 長さ部の長さ = 2byte
                //                                          ※この後2byteが値の部分の長さという意味

                // 06:2B = 値の長さ2(レングス)
                //  dec = 1579                      値の長さは1579byte
                // ※DERデータが1579byte、という意味（この4byteは含まれない）

                var response = reader.SendandResponse(new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x04 });
                if (response.IsSuccess == false) {
                    throw (new Exception("READ BINARY Error"));
                }

                // blockData-4byte + status-2byte 
                datasize = ChangeEndian.Reverse(BitConverter.ToUInt16(response.Data, 2));

                // add header-4byte
                datasize = datasize + 4;
            }

            // get block num
            int blocksize = 256;            // 決めうち！
            int blocknum = (int)Math.Ceiling(datasize / (double)blocksize);
            {
                var apdu = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
                for (int intIc = 0; intIc < blocknum; intIc++) {
                    apdu[2] = (byte)intIc;
                    var response = reader.SendandResponse(apdu);
                    if (response.IsSuccess == false) {
                        throw (new Exception("READ BINARY Error"));
                    }
                    // blockdata(256byte)
                    certDER.AddRange(response.Data.ToList());
                }
            }
            certDER = certDER.Take(datasize).ToList();

            // log
            //ParseCert(certDER.ToArray());

            return (certDER.ToArray());
        }

        private static byte[] getEF(byte[] apduSelectMF)
        {
            logger.Debug("getEF");
            byte[] certDER = null;

            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(APDU_SELECT_AP).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // select MF
                    if (reader.SendandResponse(apduSelectMF).IsSuccess == false) {
                        throw (new Exception("SELECT MF Error"));
                    }

                    // READ Cert
                    certDER = readCert(reader);
                }

            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (certDER);
        }

        private static byte[] getEFwidhPIN(byte[] apduSelectMF,byte[] apduSelectPIN,string pin)
        {
            logger.Debug("getEFwidhPIN");
            byte[] certDER = null;

            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(APDU_SELECT_AP).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // SELECT PIN IDF
                    if (reader.SendandResponse(apduSelectPIN).IsSuccess == false)
                        throw (new Exception("SELECT PIN IDF Error"));

                    // VERIFY PIN
                    {
                        byte[] pinbyte = System.Text.Encoding.ASCII.GetBytes(pin);

                        var apdu = new List<byte>();
                        apdu.AddRange(new List<byte>{ 0x00, 0x20, 0x00, 0x80 });
                        apdu.Add((byte)pinbyte.Length);
                        apdu.AddRange(pinbyte.ToList());

                        // send
                        if (reader.SendandResponse(apdu.ToArray()).IsSuccess == false) {
                            throw (new Exception("VERIFY PIN Error"));
                        }
                    }

                    // select MF
                    if (reader.SendandResponse(apduSelectMF).IsSuccess == false) {
                        throw (new Exception("SELECT MF Error"));
                    }

                    // READ Cert
                    certDER = readCert(reader);
                }

            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (certDER);
        }

        private static int getPINRetryCount(byte[] apduSelectMF)
        {
            logger.Debug("<<<getPINRetryCount>>>");
            int retrycount = -1;

            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(APDU_SELECT_AP).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // SELECT MF
                    if (reader.SendandResponse(apduSelectMF).IsSuccess == false)
                        throw (new Exception("SELECT MF Error"));

                    // VERIFY
                    var res = reader.SendandResponse(new byte[] { 0x00, 0x20, 0x00, 0x80 });
                    if (res.Sw1 == 0x63) {
                        retrycount = res.Sw2 & 0xF;
                    }
                }
            } catch (Exception ex) {
                logger.Error(ex);
                return (-9);
            }
            return (retrycount);
        }

        public static Dictionary<string,string> ParseCert(byte[] certDER)
        {
            var ret = new Dictionary<string, string>();
            try {
                var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certDER);
                //logger.Debug("X.509v3証明書の発行先であるプリンシパルの名前（古い形式）");
                //logger.Debug(x509.GetName());

                ret.Add("X.509v3証明書の形式の名前", x509.GetFormat());
                ret.Add("バージョン", $"{x509.Version}");
                ret.Add("シリアル番号", x509.GetSerialNumberString());
                ret.Add("署名アルゴリズム", x509.SignatureAlgorithm.FriendlyName);
                ret.Add("証明書を発行した証明機関の名前", x509.Issuer);
                ret.Add("サブジェクトの識別名", x509.Subject);
                ret.Add("証明書のハッシュ値の16進文字列", x509.GetCertHashString());
                ret.Add("証明書の発効日", x509.GetEffectiveDateString());
                ret.Add("証明書の失効日", x509.GetExpirationDateString());
                ret.Add("キーアルゴリズム情報", x509.GetKeyAlgorithm());
                ret.Add("キーアルゴリズムパラメータ", x509.GetKeyAlgorithmParametersString());
                ret.Add("公開鍵", x509.GetPublicKeyString());

                foreach( var extension in x509.Extensions) {
                    /*
                    if (extension.Oid.FriendlyName == "キー使用法") {
                        var ext = (X509KeyUsageExtension)extension;
                        ret.Add("Extension キー使用法", ext.KeyUsages.ToString());
                    }
                    if (extension.Oid.FriendlyName == "拡張キー使用法") {
                        var ext = (X509EnhancedKeyUsageExtension)extension;
                        string value = "";
                        var oids = ext.EnhancedKeyUsages;
                        foreach (var oid in oids) {
                            value = value + oid.FriendlyName + "(" + oid.Value + ")";
                        }
                        ret.Add("Extension 拡張キー使用法", value);
                    }
                    */

                    ret.Add($"- Extension {extension.Oid.FriendlyName}", extension.Oid.Value);
                }

                //logger.Debug("X.509v3証明書を発行した証明機関の名前(古い形式)");
                //logger.Debug(x509.GetIssuerName());

                //logger.Debug("X.509証明書全体の生データ");
                //logger.Debug(x509.GetRawCertDataString());

            } catch (Exception ex) {
                logger.Debug(ex);
            }
            return ret;
        }

        private static byte[] signature(string pin, byte[] digestSHA1, byte[] apduSelectPIN,byte[] apduSelectKey)
        {
            byte[] signature = null;

            try {
                if (pin.Length <= 0) {
                    throw new Exception("Error PIN_REQUIRED");
                }

                logger.Debug("DIGEST SHA1 ---");
                logger.Debug(Common.BytesToHexString(digestSHA1));
                logger.Debug("--- DIGEST SHA1");

                var digestInfo = createDigestInfo(digestSHA1);

                logger.Debug("DIGESTINFO ---");
                logger.Debug(Common.BytesToHexString(digestInfo));
                logger.Debug("--- DIGESTINFO");

                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(APDU_SELECT_AP).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // SELECT PIN IDF
                    if (reader.SendandResponse(apduSelectPIN).IsSuccess == false)
                        throw (new Exception("SELECT PIN IDF Error"));

                    // VERIFY PIN
                    {
                        byte[] pinbyte = System.Text.Encoding.ASCII.GetBytes(pin);

                        var apdu = new List<byte>();
                        apdu.AddRange(new List<byte> { 0x00, 0x20, 0x00, 0x80 });
                        apdu.Add((byte)pinbyte.Length);
                        apdu.AddRange(pinbyte.ToList());

                        // send
                        if (reader.SendandResponse(apdu.ToArray()).IsSuccess == false)
                            throw (new Exception("VERIFY PIN Error"));
                    }

                    // SELECT 秘密鍵IEF
                    if (reader.SendandResponse(apduSelectKey).IsSuccess == false)
                        throw (new Exception("SELECT MF Error"));

                    // COMPUTE DIGITAL SIGNATURE
                    // < 80 2A 00 80 [DigestInfo]
                    // > [SIGNATURE]
                    {
                        var apdu = new List<byte>();
                        apdu.AddRange(new List<byte> { 0x80, 0x2A, 0x00, 0x80 });
                        apdu.Add((byte)digestInfo.Length);
                        apdu.AddRange(digestInfo.ToList());
                        apdu.Add((byte)0x00);

                        var res = reader.SendandResponse(apdu.ToArray());
                        if (res.IsSuccess == false) {
                            throw (new Exception("SIGNATURE Error"));
                        }
                        signature = res.Data;
                    }
                }

            } catch (Exception ex) {
                logger.Debug(ex);
            }
            return (signature);
        }

        private static byte[] sigUsingPrivateKey(string pin, string targetFile, byte[] apduSelectPIN,byte[] apduSelectKey)
        {
            byte[] digestSHA1 = null;
            using (var fs = new System.IO.FileStream(targetFile, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
                digestSHA1 = System.Security.Cryptography.SHA1.Create().ComputeHash(fs);
            }
            return (signature(pin, digestSHA1, apduSelectPIN, apduSelectKey));
        }

        public static byte[] GetCardUID()
        {
            logger.Debug("<<<GetCardUID>>>");
            byte[] uid = null;
            try {

                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // get UID
                    var response = reader.SendandResponse(new byte[] { 0xFF, 0xCA, 0x00, 0x00, 0x00 });
                    if (response.IsSuccess) {
                        uid = response.Data;
                    }
                }
            } catch( Exception ex) {
                logger.Debug(ex);
            }
            return (uid);
        }

        public static bool IsJPKICardExist()
        {
            logger.Debug("IsJPKICardExist");
            bool ret = false;
            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(APDU_SELECT_AP).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));
                }
                ret = true;
            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (ret);
        }

        public static byte[] GetAuthenticationPublicKey()
        {
            logger.Debug("<<<GetAuthenticationPublicKey>>>");
            var cert = JPKIReaderLib.JPKIReader.GetAuthenticationCertificate();
            if (cert != null) {
                return(JPKIReaderLib.JPKIReader.GetPublicKey(cert));
            }
            return null;
        }

        public static byte[] GetAuthenticationCertificate()
        {
            logger.Debug("<<<GetAuthenticationCertificate>>>");
            return (getEF(APDU_SELECT_CERT_AUTH));
        }

        public static byte[] GetAuthenticationCA()
        {
            logger.Debug("<<<Get Authentication CA>>>");
            return (getEF(APDU_SELECT_CERT_AUTHCA));
        }

        public static byte[] GetSignaturePublicKey(string pin)
        {
            logger.Debug("<<<GetSignaturePublicKey>>>");
            var cert = JPKIReaderLib.JPKIReader.GetSignatureCertificate(pin);
            if (cert != null) {
                return (JPKIReaderLib.JPKIReader.GetPublicKey(cert));
            }
            return null;
        }

        public static byte[] GetSignatureCertificate(string pin)
        {
            logger.Debug("<<<GetSignatureCertificate>>>");
            if( pin.Length <= 0) {
                return null;
            }
            return(getEFwidhPIN(APDU_SELECT_CERT_SIG, APDU_SELECT_PIN_SIG, pin));
        }

        public static byte[] GetSignatureCA()
        {
            logger.Debug("<<<GetSignatureCA>>>");
            return (getEF(APDU_SELECT_CERT_SIGCA));
        }

        public static int GetAuthenticationPINRetryCount()
        {
            logger.Debug("<<<GetAuthenticationPINRetryCount>>>");
            return (getPINRetryCount(APDU_SELECT_PIN_AUTH));
        }

        public static int GetSignaturePINRetryCount()
        {
            logger.Debug("<<<GetSignaturePINRetryCount>>>");
            return (getPINRetryCount(APDU_SELECT_PIN_SIG));
        }

        public static byte[] GetPublicKey(byte[] certDER)
        {
            byte[] publickeyDER = null;

            try {
                // DERで取得
                List<byte> pubkey_pkcs8 = new List<byte>();
                {
                    var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certDER);

                    // ここで取れるデータはPKCS#1形式の公開鍵
                    // 先頭に
                    // 30820122300d06092a864886f70d01010105000382010f00
                    // を付加するとOpenSSLで取り扱い可能なPKCS#8になる
                    // https://qiita.com/hotpepsi/items/128f3a660cee8b5467c6
                    byte[] pubkey_pkcs1 = x509.GetPublicKey();

                    pubkey_pkcs8.AddRange(Common.HexStringToBytes("30820122300d06092a864886f70d01010105000382010f00").ToArray());
                    pubkey_pkcs8.AddRange(pubkey_pkcs1.ToArray());
                }

                publickeyDER = pubkey_pkcs8.ToArray();

            } catch (Exception ex) {
                logger.Debug(ex);
            }

            return publickeyDER;
        }

        public static byte[] SignatureUsingAuthenticationPrivateKey(string pin,string targetFile)
        {
            return (sigUsingPrivateKey(pin, targetFile, APDU_SELECT_PIN_AUTH, APDU_SELECT_KEY_AUTH));
        }

        public static byte[] SignatureUsingAuthenticationPrivateKey(string pin, byte[] targetData)
        {
            // SHA1(baseData)
            System.Security.Cryptography.SHA1 sha = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            var digestSHA1 = sha.ComputeHash(targetData);

            return(signature(pin, digestSHA1, APDU_SELECT_PIN_AUTH, APDU_SELECT_KEY_AUTH));
        }

        public static byte[] SignatureUsingSignaturePrivateKey(string pin, string targetFile)
        {
            return(sigUsingPrivateKey(pin, targetFile, APDU_SELECT_PIN_SIG, APDU_SELECT_KEY_SIG));
        }

    }
}

