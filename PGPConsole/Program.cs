using System;
using System.IO;

namespace PGPConsole
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("Encrypt Start");
            string originalPath = @"G:\dotnet\PGPConsole\PGPConsole\originalData.txt";

            string reciverPublicKey = @"G:\dotnet\PGPConsole\PGPConsole\reciver_public.txt";
            string senderPrivateKey = @"G:\dotnet\PGPConsole\PGPConsole\sender_private.txt";
            string senderSignaturePassword = "Tester";
            string originalText = File.ReadAllText(originalPath);
            byte[] outputEncrypt = PGP.UTILS.PgpManagement.Encrypt(originalText, reciverPublicKey, senderPrivateKey, senderSignaturePassword);

            // write encrypt file
            //  string encryptFileoutPut = @"G:\dotnet\PGPConsole\PGPConsole\MyTest.tmp";
            //using (MemoryStream mem = new MemoryStream(outputEncrypt)) {
            //    PGP.UTILS.PgpManagement.SaveFileStream(encryptFileoutPut, mem);
            //}


            Console.WriteLine("Encrypt End");

            Console.WriteLine("Decrypt Start");
            string cipherFilePath = @"G:\dotnet\PGPConsole\PGPConsole\MyTest.tmp";
            string reciverPrivateKey = @"G:\dotnet\PGPConsole\PGPConsole\reciver_private.txt";
            string senderPublicKey = @"G:\dotnet\PGPConsole\PGPConsole\sender_public.txt";
            string reciverSignaturePassword = "Reciver";
         //   string outputDecryptFile = @"G:\dotnet\PGPConsole\PGPConsole\output.txt";

           // byte[] cipher = File.ReadAllBytes(encryptFileoutPut);
            string decrypt = PGP.UTILS.PgpManagement.Decrypt(outputEncrypt, reciverPrivateKey, reciverSignaturePassword, senderPublicKey);
            Console.WriteLine(decrypt);
            Console.WriteLine("Decrypt End");
            Console.ReadLine();
        }
    }
}