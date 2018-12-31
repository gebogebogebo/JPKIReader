using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using JPKIReaderLib;

namespace testUI01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void setResponse(byte[] addu, APDUresponse res)
        {
            string msg = "<Command>\r\n" + JPKIReaderLib.Common.BytesToHexString(addu) + "\r\n\r\n";

            msg = msg + "<Response>\r\n";
            msg = msg + string.Format($"IsSuccess={res.IsSuccess},Message={res.Message} \r\n");
            msg = msg + string.Format($"SW1=0x{res.Sw1:X2},SW2=0x{res.Sw2:X2} \r\n<ResponseData>\r\n");
            msg = msg + JPKIReaderLib.Common.BytesToHexString(res.Data) + "\r\n";
            textBox.Text = textBox.Text + msg + "\r\n";
        }
        private void log(string log)
        {
            textBox.Text = textBox.Text + log + "\r\n";
        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            var uid = JPKIReaderLib.JPKIReader.GetCardUID();
            if( uid != null) {
                var uidstr = JPKIReaderLib.Common.BytesToHexString(uid);
                log(string.Format($"UID={uidstr}"));

            } else {
                log(string.Format($"error"));
            }
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            var certDER = JPKIReaderLib.JPKIReader.GetAuthenticationCertificate();
            if( certDER != null) {
                // Export
                Common.ExportHextoFile(@".\Authentication_Certificate_DER.hex", certDER.ToArray());

                var certPEM = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(certDER.ToArray());
                System.IO.File.WriteAllText(@".\Authentication_Certificate_PEM.pem", certPEM);

                log("GetAuthenticationCertificate() -> OK");
                log(certPEM);
            } else {
                log("GetAuthenticationCertificate() -> Error");
            }
        }

        private void button3_Click(object sender, RoutedEventArgs e)
        {
            var certDER = JPKIReaderLib.JPKIReader.GetAuthenticationCA();
            if (certDER != null) {
                // Export
                Common.ExportHextoFile(@".\Authentication_Certificate_DER.hex", certDER.ToArray());

                var certPEM = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(certDER.ToArray());
                System.IO.File.WriteAllText(@".\Authentication_Certificate_PEM.pem", certPEM);

                log("GetAuthenticationCA() -> OK");
                log(certPEM);
            } else {
                log("GetAuthenticationCA() -> Error");
            }
        }

        private void button4_Click(object sender, RoutedEventArgs e)
        {
            var certDER = JPKIReaderLib.JPKIReader.GetSignatureCertificate();
            if (certDER != null) {
                // Export
                Common.ExportHextoFile(@".\Signature_CA_DER.hex", certDER.ToArray());

                var certPEM = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(certDER.ToArray());
                System.IO.File.WriteAllText(@".\Signature_CA_PEM.pem", certPEM);

                log("GetSignatureCertificate() -> OK");
                log(certPEM);
            } else {
                log("GetSignatureCertificate() -> Error");
            }
        }

        private void button5_Click(object sender, RoutedEventArgs e)
        {
            var certDER = JPKIReaderLib.JPKIReader.GetSignatureCA();
            if (certDER != null) {
                // Export
                Common.ExportHextoFile(@".\Signature_CA_DER.hex", certDER.ToArray());

                var certPEM = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(certDER.ToArray());
                System.IO.File.WriteAllText(@".\Signature_CA_PEM.pem", certPEM);

                log("GetSignatureCA() -> OK");
                log(certPEM);

            } else {
                log("GetSignatureCA() -> Error");
            }
        }

        private void button6_Click(object sender, RoutedEventArgs e)
        {
            var count = JPKIReaderLib.JPKIReader.GetAuthenticationPINRetryCount();
            log(string.Format($"GetAuthenticationPINRetryCount() -> {count}"));
        }

        private void button7_Click(object sender, RoutedEventArgs e)
        {
            var count = JPKIReaderLib.JPKIReader.GetSignaturePINRetryCount();
            log(string.Format($"GetSignaturePINRetryCount() -> {count}"));
        }
    }
}
