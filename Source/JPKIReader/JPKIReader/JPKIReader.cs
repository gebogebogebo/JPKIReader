using System;
using System.Collections.Generic;
using System.Linq;

namespace JPKIReaderLib
{
    public class JPKIReader : ICReader
    {
        private static byte[] getEF(byte[] apduSelectMF)
        {
            logger.Debug("getEF");
            var certDER = new List<byte>();

            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(new byte[] { 0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01 }).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // select MF
                    if (reader.SendandResponse(apduSelectMF).IsSuccess == false) {
                        throw (new Exception("SELECT MF Error"));
                    }

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

                        // 06:2B = 値の長さ1(レングス)
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
                    int blocksize = 256;
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
                }

            } catch (Exception ex) {
                logger.Error(ex);
                return (null);
            }
            return (certDER.ToArray());
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
                    if (reader.SendandResponse(new byte[] { 0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01 }).IsSuccess == false)
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

        public static byte[] GetCardUID()
        {
            logger.Debug("<<<GetCardUID>>>");

            byte[] uid = null;
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
            return (uid);
        }

        public static byte[] GetAuthenticationCertificate()
        {
            logger.Debug("<<<GetAuthenticationCertificate>>>");
            return (getEF(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0A }));
        }

        public static byte[] GetAuthenticationCA()
        {
            logger.Debug("<<<Get Authentication CA>>>");
            return (getEF(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0B }));
        }

        public static byte[] GetSignatureCertificate()
        {
            logger.Debug("<<<GetSignatureCertificate>>>");
            return (getEF(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x01 }));
        }

        public static byte[] GetSignatureCA()
        {
            logger.Debug("<<<GetSignatureCA>>>");
            return (getEF(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x02 }));
        }

        public static int GetAuthenticationPINRetryCount()
        {
            logger.Debug("<<<GetAuthenticationPINRetryCount>>>");
            return (getPINRetryCount(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x18 }));
        }

        public static int GetSignaturePINRetryCount()
        {
            logger.Debug("<<<GetSignaturePINRetryCount>>>");
            return (getPINRetryCount(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1B }));
        }

    }
}
