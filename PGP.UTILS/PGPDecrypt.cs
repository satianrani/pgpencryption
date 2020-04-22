using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Text;

namespace PGP.UTILS
{
    public class PGPDecrypt
    {
        public string _encryptedFilePath;
        public byte[] _encrypted;
        public string _privKeyPath;
        public char[] _password;
        public string _outputPath;
        public PgpEncryptionKeys pgpKeys;

        public PGPDecrypt(string encryptedFilePath, string privKeyPath, string password, string outputPath, string pubKeyPath)
        {
            _encryptedFilePath = encryptedFilePath;
            _outputPath = outputPath;
            _password = password.ToCharArray();
            _privKeyPath = privKeyPath;
            pgpKeys = new PgpEncryptionKeys(pubKeyPath, privKeyPath, password);
        }

        public PGPDecrypt(byte[] encrypted, string privKeyPath, string password, string pubKeyPath)
        {
            _encrypted = encrypted;
            _password = password.ToCharArray();
            _privKeyPath = privKeyPath;
            pgpKeys = new PgpEncryptionKeys(pubKeyPath, privKeyPath, password);
        }

        public string decryptToString(byte[] cipher)
        {
            string output = string.Empty;
            
            try
            {
                using (Stream cipherStream = new MemoryStream(cipher))
                {
                    Stream input = PgpUtilities.GetDecoderStream(cipherStream);
                    PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
                    PgpEncryptedDataList enc;
                    PgpObject obj = pgpObjF.NextPgpObject();
                    if (obj is PgpEncryptedDataList)
                    {
                        enc = (PgpEncryptedDataList)obj;
                    }
                    else
                    {
                        enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
                    }
                    PgpPrivateKey privKey = pgpKeys.PrivateKey;
                    //PgpPublicKeyEncryptedData pbe = enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First();
                    PgpPublicKeyEncryptedData pbe = null;
                    foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                    {
                        if (privKey != null)
                        {
                            pbe = pked;
                            break;
                        }
                    }
                    using (Stream clear = pbe.GetDataStream(privKey))
                    {
                        PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                        PgpObject message = plainFact.NextPgpObject();

                        if (message is PgpCompressedData)
                        {
                            PgpCompressedData cData = (PgpCompressedData)message;
                            Stream compDataIn = cData.GetDataStream();
                            PgpObjectFactory o = new PgpObjectFactory(compDataIn);
                            message = o.NextPgpObject();
                            if (message is PgpOnePassSignatureList)
                            {
                                message = o.NextPgpObject();
                            }
                            PgpLiteralData Ld = null; 
                            Ld = (PgpLiteralData)message; 
                            using (MemoryStream decoded = new MemoryStream())
                            {
                                Stream unc = Ld.GetInputStream();
                                Streams.PipeAll(unc, decoded);
                                byte[] data = decoded.ToArray();
                                if (data != null)
                                {
                                    output = Encoding.UTF8.GetString(data);
                                }
                            }
                        }
                    }
                    input.Close();
                }
                
                return output;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public void decrypt(Stream input)
        {
            input = PgpUtilities.GetDecoderStream(input);
            try
            {
                PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
                PgpEncryptedDataList enc;
                PgpObject obj = pgpObjF.NextPgpObject();
                if (obj is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)obj;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
                }
                PgpPrivateKey privKey = pgpKeys.PrivateKey;
                //PgpPublicKeyEncryptedData pbe = enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First();
                PgpPublicKeyEncryptedData pbe = null;
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    if (privKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }
                using (Stream clear = pbe.GetDataStream(privKey))
                {
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData)
                    {
                        PgpCompressedData cData = (PgpCompressedData)message;
                        Stream compDataIn = cData.GetDataStream();
                        PgpObjectFactory o = new PgpObjectFactory(compDataIn);
                        message = o.NextPgpObject();
                        if (message is PgpOnePassSignatureList)
                        {
                            message = o.NextPgpObject();
                        }
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        //  using (Stream output = File.Create(_outputPath + "\\" + Ld.FileName))
                        if (File.Exists(_outputPath))
                        {
                            File.Delete(_outputPath);
                        }
                        using (Stream output = File.Create(_outputPath))
                        {
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                }
 
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }
    }
}