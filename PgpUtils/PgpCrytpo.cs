using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PgpUtils
{
    public class PgpCrytpo
    {
        public static byte[] readFile(string fileName)
        {
            return File.ReadAllBytes(fileName);
        }

        public static void Encrypt(string fileOriginalPath, string encryptFileoutPut, string reciverPublicKey, string senderPrivateKey, string senderSignaturePassword)
        {
            FileInfo fi = new FileInfo(fileOriginalPath);
            using (FileStream str = new FileStream(encryptFileoutPut, FileMode.Create))
            {
                PgpEncryptionKeys objPgpEncryptionKeys = new PgpEncryptionKeys(reciverPublicKey, senderPrivateKey, senderSignaturePassword);
                PgpEncrypt objPgpEncrypt = new PgpEncrypt(objPgpEncryptionKeys);
                objPgpEncrypt.EncryptAndSign(str, fi);
                str.Flush();
                str.Close();
            }
        }

        public static void Decrypt(string cipherFilePath, string reciverPrivateKey, string reciverSignaturePassword, string outputDecryptFile, string senderPublicKey)
        {
            PGPDecrypt test = new PGPDecrypt(cipherFilePath,
                                               reciverPrivateKey,
                                               reciverSignaturePassword,
                                               outputDecryptFile,
                                               senderPublicKey);
            using (FileStream fs = File.Open(cipherFilePath, FileMode.Open))
            {
                test.decrypt(fs);
                fs.Close();
            }
        }
    }
}
