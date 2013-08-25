using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAwpf
{
    public class RSAHelper
    {
        public string PublicKey, PrivateKey;

        public const int KeySize = 2048;
        RSACryptoServiceProvider rsaProvider;
        public void Initial()
        {
            //声明一个RSA算法的实例，由RSACryptoServiceProvider类型的构造函数指定了密钥长度为1024位
            //实例化RSACryptoServiceProvider后，RSACryptoServiceProvider会自动生成密钥信息。
            rsaProvider = new RSACryptoServiceProvider(KeySize);
            //将RSA算法的公钥导出到字符串PublicKey中，参数为false表示不导出私钥
            PublicKey = rsaProvider.ToXmlString(false);
            //将RSA算法的私钥导出到字符串PrivateKey中，参数为true表示导出私钥
            PrivateKey = rsaProvider.ToXmlString(true);
        }

        public int MaxEncryptSize
        {
            get
            {
               return rsaProvider.KeySize / 8 - 11;
            }
        }

        public byte[] EncryptData(byte[] data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize);
            //将公钥导入到RSA对象中，准备加密；
            rsa.FromXmlString(PublicKey);
            //对数据data进行加密，并返回加密结果；
            //第二个参数用来选择Padding的格式
            return rsa.Encrypt(data, false);
        }


        //public byte[] EncryptDataWithPrivateKey(byte[] data)
        //{
        //    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize);
        //    //用私钥加密
        //    rsa.FromXmlString(PrivateKey);
        //    return rsa.Encrypt(data, false);
        //}


        //public byte[] DecryptDataWithPublicKey(byte[] data)
        //{
        //    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize);
        //    //将公钥导入RSA中，准备解密；
        //    rsa.FromXmlString(PublicKey);
        //    //对数据进行解密，并返回解密结果；
        //    return rsa.Decrypt(data, false);
        //}

        public byte[] DecryptData(byte[] data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize);
            //将私钥导入RSA中，准备解密；
            rsa.FromXmlString(PrivateKey);
            //对数据进行解密，并返回解密结果；
            return rsa.Decrypt(data, false);
        }

        public byte[] Sign(byte[] data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize);
            //导入私钥，准备签名
            rsa.FromXmlString(PrivateKey);
            //将数据使用MD5进行消息摘要，然后对摘要进行签名并返回签名数据
            return rsa.SignData(data, "MD5");
        }

        public bool Verify(byte[] data, byte[] Signature)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize);
            //导入公钥，准备验证签名
            rsa.FromXmlString(PublicKey);
            //返回数据验证结果
            return rsa.VerifyData(data, "MD5", Signature);
        }

    }
}
