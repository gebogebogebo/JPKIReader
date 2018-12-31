using System;
using System.Collections.Generic;
using System.Linq;

namespace JPKIReaderLib
{
    public class ICReader : IDisposable
    {
        protected static NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        private IntPtr context = IntPtr.Zero;
        private string targetReaderName = "";
        private IntPtr handle = IntPtr.Zero;
        private byte[] recvBuff;

        public ICReader()
        {
            create();
        }
        public ICReader(string targetReaderName)
        {
            create();
            this.targetReaderName = targetReaderName;
        }

        private bool create()
        {
            SCardResult result = SCardAPI.SCardEstablishContext(SCardAPI.SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out this.context);
            if (result != SCardResult.SCARD_S_SUCCESS) {
                logger.Error("SCardEstablishContext");
                this.context = IntPtr.Zero;
                return false;
            }
            return true;
        }

        private static void logResponse(byte[] addu, APDUresponse res)
        {
            logger.Debug(string.Format($"SendAPDU={Common.BytesToHexString(addu)}"));
            logger.Debug(string.Format($"IsSuccess={res.IsSuccess}"));
            logger.Debug(string.Format($"Message={res.Message}"));
            logger.Debug(string.Format($"SW1=0x{res.Sw1:X2},SW2=0x{res.Sw2:X2}"));
            logger.Debug(string.Format($"Data={Common.BytesToHexString(res.Data)}"));
        }

        public void Dispose()
        {
            Disconnect();
            if (this.context != IntPtr.Zero) {
                SCardAPI.SCardReleaseContext(this.context);
                this.context = IntPtr.Zero;
            }
        }

        public bool Connect()
        {
            bool ret = false;
            try {
                if(isLinkedDevice() == false ) {
                    return false;
                }

                uint protocol;
                var result = SCardAPI.SCardConnect(this.context, this.targetReaderName, SCardAPI.SCARD_SHARE_SHARED, SCardAPI.SCARD_PROTOCOL_T1, out handle, out protocol);
                if (result != SCardResult.SCARD_S_SUCCESS) {
                    throw (new Exception("SCardConnect"));
                }

                this.recvBuff = new byte[1024];

                ret = true;
            } catch (Exception ex) {
                logger.Error(ex);
            }
            return ret;
        }

        public bool Disconnect()
        {
            if (this.handle != IntPtr.Zero) {
                var result = SCardAPI.SCardDisconnect(this.handle, SCardAPI.SCARD_LEAVE_CARD);
                if (result == SCardResult.SCARD_S_SUCCESS) {
                    this.handle = IntPtr.Zero;
                    this.recvBuff = null;
                    return true;
                }
            }
            return false;
        }

        public APDUresponse SendandResponse(byte[] apdu)
        {
            APDUresponse res = null;
            try {
                int recvSize = SCardAPI.SCardTransmit(this.handle, apdu, this.recvBuff);
                res = new APDUresponse(recvBuff, recvSize);
            } catch (Exception ex) {
                logger.Error(ex);
            } finally {
                logResponse(apdu, res);
            }
            return res;
        }

        private bool isLinkedDevice()
        {
            bool ret = false;
            try {
                if( this.context == IntPtr.Zero) {
                    return false;
                }

                // get size
                uint readerSize = 0;
                var result = SCardAPI.SCardListReaders(this.context, null, null, ref readerSize);
                if (result != SCardResult.SCARD_S_SUCCESS) {
                    throw (new Exception("SCardListReaders"));
                }

                // get readerData
                char[] readerData = new char[readerSize];
                result = SCardAPI.SCardListReaders(this.context, null, readerData, ref readerSize);
                if (result != SCardResult.SCARD_S_SUCCESS) {
                    throw (new Exception("SCardListReaders"));
                }

                // リーダー・ライターの名称分割(\u0000で区切られている)
                string[] readers = getNames(readerData);
                if( readers.Count() <= 0) {
                    throw (new Exception("getNames"));
                }

                // select target
                bool find = false;
                {
                    if( string.IsNullOrEmpty(targetReaderName) ) {
                        this.targetReaderName = readers[0];
                        find = true;
                    } else {
                        foreach (string readerName in readers) {
                            if (readerName.StartsWith(this.targetReaderName, StringComparison.OrdinalIgnoreCase)) {
                                find = true;
                                break;
                            }
                        }
                    }
                }
                ret = find;

            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (ret);
        }

        private static string[] getNames(char[] source)
        {
            if (source == null) {
                return new string[0];
            } else {
                string create = new String(source);
                List<string> result = new List<string>();
                foreach (string element in create.Split('\u0000')) {
                    if (!String.IsNullOrEmpty(element)) {
                        result.Add(element);
                    }
                }
                return result.ToArray();
            }
        }
    }
}
