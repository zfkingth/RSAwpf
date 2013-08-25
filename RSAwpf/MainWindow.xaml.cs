using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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


namespace RSAwpf
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        RSAHelper helper = new RSAHelper();
        UnicodeEncoding encoding = new UnicodeEncoding();
        const string pubFileName = "public.xls";
        const string priFileName = "private.xls";
        const string encSuffix = "_encrypted";
        const string decSuffix = "_decrypted";
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            helper.Initial();
            //save to file
            string path = txtPath.Text.Trim();

            if (System.IO.Directory.Exists(path) == false)
            {
                System.IO.Directory.CreateDirectory(path);
            }

            using (System.IO.FileStream pfile = System.IO.File.Create(System.IO.Path.Combine(path, pubFileName)))
            {

                byte[] buffer = encoding.GetBytes(helper.PublicKey);
                pfile.Write(buffer, 0, buffer.Length);
                pfile.Close();
            }

            using (System.IO.FileStream sfile = System.IO.File.Create(System.IO.Path.Combine(path, priFileName)))
            {

                byte[] buffer = encoding.GetBytes(helper.PrivateKey);
                sfile.Write(buffer, 0, buffer.Length);
                sfile.Close();
            }
            tbResult.Text = "操作成功.";


        }


        /// <summary>
        /// encrypt
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            byte[] buffer = null;



            using (System.IO.FileStream fs = System.IO.File.OpenRead(tbPublic.Text.Trim()))
            {
                using (System.IO.BinaryReader br = new System.IO.BinaryReader(fs))
                {
                    buffer = br.ReadBytes((int)fs.Length);
                    helper.PublicKey = encoding.GetString(buffer);


                }
            }

            string encFilePath=tbEnc.Text.Trim();

            //get file which is being encrypting
            using (System.IO.FileStream fs = System.IO.File.OpenRead(encFilePath))
            {
                using (System.IO.BinaryReader br = new System.IO.BinaryReader(fs))
                {
                    buffer = br.ReadBytes((int)fs.Length);



                }
            }

            //write encrypted data to file
            using (System.IO.FileStream fs = System.IO.File.OpenWrite(encFilePath + encSuffix))
            {
                using (System.IO.BinaryWriter bw = new System.IO.BinaryWriter(fs))
                {

                    int i = 0;
                    //每次加密的block 大小
                    int blocksize =210;//<size/8-41
                    int currentSize;
                    do
                    {
                        if (i + blocksize <= buffer.Length)
                        {
                            currentSize = blocksize;
                        }
                        else
                        {
                            currentSize = buffer.Length % blocksize;
                        }
                        byte[] blockBuffer = new byte[currentSize];
                        Array.Copy(buffer, i, blockBuffer, 0, currentSize);
                        var temp = helper.EncryptData(blockBuffer);

                        bw.Write(temp);
                        i += blocksize;
                    } while (i < buffer.Length);

                    bw.Close();
                }

                tbResult.Text = "操作完成";
            }

        }

        /// <summary>
        /// decrypt
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            byte[] buffer = null;





            using (System.IO.FileStream fs = System.IO.File.OpenRead(tbPrivate.Text.Trim()))
            {
                using (System.IO.BinaryReader br = new System.IO.BinaryReader(fs))
                {
                    buffer = br.ReadBytes((int)fs.Length);
                    helper.PrivateKey = encoding.GetString(buffer);


                }
            }



            string decFilePath = tbDec.Text.Trim();

            //get file which is being encrypting
            using (System.IO.FileStream fs = System.IO.File.OpenRead(decFilePath))
            {
                using (System.IO.BinaryReader br = new System.IO.BinaryReader(fs))
                {
                    buffer = br.ReadBytes((int)fs.Length);



                }
            }


            using (System.IO.FileStream fs = System.IO.File.OpenWrite(decFilePath + decSuffix))
            {
                using (System.IO.BinaryWriter bw = new System.IO.BinaryWriter(fs))
                {

                    int i = 0;
                    //每次加密的block 大小
                    int blocksize = RSAHelper.KeySize / 8;
                    int currentSize;
                    do
                    {
                        if (i + blocksize <= buffer.Length)
                        {
                            currentSize = blocksize;
                        }
                        else
                        {
                            currentSize = buffer.Length % blocksize;
                        }
                        byte[] blockBuffer = new byte[currentSize];
                        Array.Copy(buffer, i, blockBuffer, 0, currentSize);
                        var temp = helper.DecryptData(blockBuffer);

                        bw.Write(temp);
                        i += blocksize;
                    } while (i < buffer.Length);

                    bw.Close();
                }

                tbResult.Text = "操作完成";
            }

        }





    }
}
