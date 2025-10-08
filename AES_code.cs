// code template copied from https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-8.0
using System;
using System.IO;
using System.Security.Cryptography;

namespace Aes_Example
{
    class AesExample
    {
        public static void Main()
        {
            Console.WriteLine("Enter data string to encrypt:");
            string dataToEncrypt = Console.ReadLine();

            // Create a new instance of the Aes class.
            // This generates a new key and initialization vector (IV).
            using (Aes myAes = Aes.Create())
            {

                // Encrypt the string to an array of bytes.
                byte[] encryptedData = EncryptStringToBytes_Aes(dataToEncrypt, myAes.Key, myAes.IV);


                // Decrypt the bytes to a string.
                string decryptedData = DecryptStringFromBytes_Aes(encryptedData, myAes.Key, myAes.IV);

                //Display the plaintext data
                Console.WriteLine("Plaintext: {0}", dataToEncrypt);
                
                // Display the secret encryption algorithm variables
                Console.WriteLine("----- BEGIN ENCRYPTION ALGORITHM DETAILS -----");
                Console.WriteLine("Secret Key: {0}", ToReadableByteArray(myAes.Key));
                Console.WriteLine("Secret Intialization Vector (IV): {0}", ToReadableByteArray(myAes.IV));
                Console.WriteLine("Encrypted Data: {0}", ToReadableByteArray(encryptedData));
                Console.WriteLine("------ END ENCRYPTION ALGORITHM DETAILS ------");

                Console.WriteLine("Decrypted data: {0}", decryptedData);
            }
        }
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encryptedData;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                    }

                    encryptedData = msEncrypt.ToArray();
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encryptedData;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        // This function copied verbatim from this stack overflow: 
        // https://stackoverflow.com/questions/10940883/converting-byte-array-to-string-and-printing-out-to-console
        // this converts the byte array of these encryption factors 
        // to readable number strings to be printed to the console:
        // encrypted data, secret key, and IV
        static public string ToReadableByteArray(byte[] bytes)
        {
            return string.Join(", ", bytes);
        }
    }
}