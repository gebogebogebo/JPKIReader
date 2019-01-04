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

        private string getWorkDir()
        {
            string path = textBoxWorkDir.Text;
            if (string.IsNullOrEmpty(path)) {
                return (".");
            }

            if (System.IO.Directory.Exists(path) == false) {
                System.IO.Directory.CreateDirectory(path);
            }
            return path;
        }

        // Get UID
        private void button1_Click(object sender, RoutedEventArgs e)
        {
            var uid = JPKIReaderLib.JPKIReader.GetCardUID();
            if( uid != null) {
                var uidstr = JPKIReaderLib.Common.BytesToHexString(uid);
                MessageBox.Show(string.Format($"UID={uidstr}"));
            } else {
                MessageBox.Show("GetCardUID Failed!");
            }
        }

        // Check JPKI
        private void buttonCheckJPKI_Click(object sender, RoutedEventArgs e)
        {
            if (JPKIReaderLib.JPKIReader.IsJPKICardExist()) {
                MessageBox.Show("Check JPKI Success!");
            } else {
                MessageBox.Show("Check JPKI Failed!");
            }
        }

        // Get Auth Public Key
        private void button9_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = JPKIReaderLib.JPKIReader.GetAuthenticationPublicKey();
            if (der != null) {
                System.IO.File.WriteAllBytes(workDir+@".\Authentication_PublicKey.der", der);

                var pem = JPKIReaderLib.Common.ConvertPublicKeyDERtoPEM(der);
                System.IO.File.WriteAllText(workDir + @".\Authentication_PublicKey.pem", pem);

                MessageBox.Show("Get Auth Public Key Success!");
            } else {
                MessageBox.Show("Get Auth Public Key Failed!");
            }
        }

        // Get Authentication Certificate
        private void button2_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = JPKIReaderLib.JPKIReader.GetAuthenticationCertificate();
            if( der != null) {

                // Export
                System.IO.File.WriteAllBytes(workDir + @".\Authentication_Certificate.der", der);

                JPKIReaderLib.Common.ExportHextoFile(workDir+@"\Authentication_Certificate.hex", der.ToArray());

                var pem = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(der.ToArray());
                System.IO.File.WriteAllText(workDir+@"\Authentication_Certificate.pem", pem);

                MessageBox.Show("Get Authentication Certificate Success!");
            } else {
                MessageBox.Show("Get Authentication Certificate Failed!");
            }
        }

        // Get Authentication CA
        private void button3_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = JPKIReaderLib.JPKIReader.GetAuthenticationCA();
            if (der != null) {
                // Export
                JPKIReaderLib.Common.ExportHextoFile(workDir+@"\Authentication_CA_DER.hex", der.ToArray());

                var pem = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(der.ToArray());
                System.IO.File.WriteAllText(workDir+@"\Authentication_CA_PEM.pem", pem);

                MessageBox.Show("Get Authentication CA Success!");
            } else {
                MessageBox.Show("Get Authentication CA Failed!");
            }
        }

        // Get Sig Public Key
        private void button10_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = JPKIReaderLib.JPKIReader.GetSignaturePublicKey(textBoxSigPIN.Text);
            if (der != null) {
                System.IO.File.WriteAllBytes(workDir + @"\Signature_PublicKey.der", der);

                var pem = JPKIReaderLib.Common.ConvertPublicKeyDERtoPEM(der);
                System.IO.File.WriteAllText(workDir + @"\Signature_PublicKey.pem", pem);

                MessageBox.Show("Get Sig Public Key Success!");
            } else {
                MessageBox.Show("Get Sig Public Key Failed!");
            }
        }

        // Get Sig Certificate
        private void button4_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = JPKIReaderLib.JPKIReader.GetSignatureCertificate(textBoxSigPIN.Text);
            if (der != null) {
                // Export
                JPKIReaderLib.Common.ExportHextoFile(workDir + @"\Signature_Certificate_DER.hex", der.ToArray());

                var pem = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(der.ToArray());
                System.IO.File.WriteAllText(workDir+@".\Signature_Certificate_PEM.pem", pem);

                MessageBox.Show("Get Sig Certificate Success!");
            } else {
                MessageBox.Show("Get Sig Certificate Failed!");
            }
        }

        // GetSignatureCA
        private void button5_Click(object sender, RoutedEventArgs e)
        {
            var der = JPKIReaderLib.JPKIReader.GetSignatureCA();
            if (der != null) {
                // Export
                JPKIReaderLib.Common.ExportHextoFile(@".\Signature_CA_DER.hex", der.ToArray());

                var pem = JPKIReaderLib.Common.ConvertCertificateDERtoPEM(der.ToArray());
                System.IO.File.WriteAllText(@".\Signature_CA_PEM.pem", pem);

                MessageBox.Show("Get Signature CA Success!");
            } else {
                MessageBox.Show("Get Signature CA Failed!");
            }
        }

        // GetAuthenticationPINRetryCount
        private void button6_Click(object sender, RoutedEventArgs e)
        {
            var count = JPKIReaderLib.JPKIReader.GetAuthenticationPINRetryCount();
            MessageBox.Show(string.Format($"Authentication PIN Retry -> {count}"));
        }

        // GetSignaturePINRetryCount
        private void button7_Click(object sender, RoutedEventArgs e)
        {
            var count = JPKIReaderLib.JPKIReader.GetSignaturePINRetryCount();
            MessageBox.Show(string.Format($"Signature PIN Retry -> {count}"));
        }

        // Signature using Auth Private Key
        private void button8_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            string file = "";
            {
                var dialog = new Microsoft.Win32.OpenFileDialog();
                if (dialog.ShowDialog() == true) {
                    file = dialog.FileName;
                } else {
                    return;
                }
            }

            // ファイルの電子署名を得る
            var sig = JPKIReaderLib.JPKIReader.SignatureUsingAuthenticationPrivateKey(textBoxAuthPIN.Text, file);
            if ( sig != null) {
                // Export
                var title = System.IO.Path.GetFileNameWithoutExtension(file);
                System.IO.File.WriteAllBytes(workDir+$@".\{title}_Sig_using_Auth_PrivateKey.sig", sig);
                // Common.ExportHextoFile(@".\Sig_using_Auth_PrivateKey.hex", sig);

                MessageBox.Show("Signature using Auth Private Key Success!");
            } else {
                MessageBox.Show("Signature using Auth Private Key Failed!");
            }
        }

        // Signature using Sig Private Key
        private void button11_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            string file = "";
            {
                var dialog = new Microsoft.Win32.OpenFileDialog();
                if (dialog.ShowDialog() == true) {
                    file = dialog.FileName;
                } else {
                    return;
                }
            }

            // ファイルの電子署名を得る
            var sig = JPKIReaderLib.JPKIReader.SignatureUsingSignaturePrivateKey(textBoxSigPIN.Text, file);
            if (sig != null) {
                // Export
                var title = System.IO.Path.GetFileNameWithoutExtension(file);
                System.IO.File.WriteAllBytes(workDir + $@"\{title}_Sig_using_Sig_PrivateKey.sig", sig);

                MessageBox.Show("Signature using Sig Private Key Success!");
            } else {
                MessageBox.Show("Signature using Sig Private Key Failed!");
            }
        }

        // verify
        private void buttonVerify_Click(object sender, RoutedEventArgs e)
        {
            try {
                var pubkeyder = System.IO.File.ReadAllBytes(textPubKey.Text);

                byte[] signature = System.IO.File.ReadAllBytes(textSig.Text);

                string targetFile = textTargetFile.Text;

                if( JPKIReaderLib.Verify.VerifySignature(pubkeyder, signature, targetFile)) {
                    MessageBox.Show("Verify Success!");
                } else {
                    MessageBox.Show("Verify Failed!");
                }
            } catch ( Exception) {
                MessageBox.Show("Verify Failed.Exception Error has occurred");
            }
        }

        private void buttonPubKey_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true) {
                textPubKey.Text = dialog.FileName;
            }
        }

        private void buttonSig_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true) {
                textSig.Text = dialog.FileName;
            }
        }

        private void buttonTargetFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true) {
                textTargetFile.Text = dialog.FileName;
            }
        }

    }
}
