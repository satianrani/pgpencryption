using System;
using System.IO;

namespace PGP.UTILS
{
    public class PgpManagement
    {
        public static byte[] readFile(string fileName)
        {
            return File.ReadAllBytes(fileName);
        }

        public static void EncryptAndWriteFile(string originalText, string encryptFileoutPut, string reciverPublicKey, string senderPrivateKey, string senderSignaturePassword)
        {
            using (MemoryStream str = new MemoryStream())
            {
                PgpEncryptionKeys objPgpEncryptionKeys = new PgpEncryptionKeys(reciverPublicKey, senderPrivateKey, senderSignaturePassword);
                PgpEncrypt objPgpEncrypt = new PgpEncrypt(objPgpEncryptionKeys);
                objPgpEncrypt.EncryptAndSign(str, originalText);
                Console.WriteLine(str.ToArray().Length); 
                SaveFileStream(encryptFileoutPut, str);
                str.Flush();
                str.Close();
            }
        }

        public static byte[] Encrypt(string originalText, string reciverPublicKey, string senderPrivateKey, string senderSignaturePassword)
        {
            // FileInfo fi = new FileInfo(fileOriginalPath);
            // using (FileStream str = new FileStream(encryptFileoutPut, FileMode.Create))
            byte[] data;
            using (MemoryStream str = new MemoryStream())
            {
                PgpEncryptionKeys objPgpEncryptionKeys = new PgpEncryptionKeys(reciverPublicKey, senderPrivateKey, senderSignaturePassword);
                PgpEncrypt objPgpEncrypt = new PgpEncrypt(objPgpEncryptionKeys);
                objPgpEncrypt.EncryptAndSign(str, originalText);
                Console.WriteLine(str.ToArray().Length);
                data = str.ToArray();
                str.Flush();
                str.Close();
            }
            return data;
        }

        public static void SaveFileStream(String path, MemoryStream stream)
        {
            var fileStream = new FileStream(path, FileMode.Create, FileAccess.Write);
            stream.WriteTo(fileStream);
            fileStream.Dispose();
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

        public static string Decrypt(byte[] cipher, string reciverPrivateKey, string reciverSignaturePassword, string senderPublicKey)
        {
            PGPDecrypt test = new PGPDecrypt(cipher,
                                               reciverPrivateKey,
                                               reciverSignaturePassword,
                                               senderPublicKey);

            return test.decryptToString(cipher);
        }
    }
}