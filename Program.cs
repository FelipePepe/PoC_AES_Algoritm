using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AES
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string originalText = "Hello, AES!";
            //string key = "0123456789ABCDEF"; // 128-bit key (16 bytes)
            byte[] key = GenerateRandomKey();

            Console.WriteLine("Original Text: " + originalText);

            byte[] encryptedBytes = Encrypt(originalText, key);
            string encryptedText = Convert.ToBase64String(encryptedBytes);

            Console.WriteLine("Encrypted Text: " + encryptedText);

            string decryptedText = Decrypt(encryptedBytes, key);

            Console.WriteLine("Decrypted Text: " + decryptedText);

            Console.Read();
        }

        static byte[] GenerateRandomKey()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256; // Puedes ajustar la longitud de la clave aquí
                aesAlg.GenerateKey();
                return aesAlg.Key;
            }
        }

        static byte[] Encrypt(string plainText, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                //aesAlg.Key = Encoding.UTF8.GetBytes(key);
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                // Generar un IV aleatorio y almacenarlo para usarlo en el descifrado
                aesAlg.GenerateIV();
                byte[] iv = aesAlg.IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }

                    // Concatenar el IV a los datos cifrados antes de devolverlos
                    return iv.Concat(msEncrypt.ToArray()).ToArray();
                }
            }
        }

        static string Decrypt(byte[] cipherTextWithIV, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                //aesAlg.Key = Encoding.UTF8.GetBytes(key);
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                // Extraer el IV de los primeros 16 bytes de los datos cifrados
                byte[] iv = cipherTextWithIV.Take(16).ToArray();
                byte[] cipherText = cipherTextWithIV.Skip(16).ToArray();

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
