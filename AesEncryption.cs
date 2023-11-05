using Lunacy.Encryption.Models;
using System.Security.Cryptography;
using System.Text;

namespace Lunacy.Encryption {
    public static class AesEncryption {
        public static AesKey GenerateKey() {
            using Aes aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();

            return new AesKey(aes.Key, aes.IV);
        }

        public static AesKey GenerateKeyFromPwd(string password, Memory<byte> iv) {
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            using Rfc2898DeriveBytes rfc = new(password, salt, iterations: 10000, HashAlgorithmName.SHA256);
            return new AesKey {
                Key = rfc.GetBytes(256 / 8),
                IV = iv.ToArray()
            };
        }

        public static AesKey GenerateKeyFromPwd(string password) {
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            using Rfc2898DeriveBytes rfc = new(password, salt, iterations: 10000, HashAlgorithmName.SHA256);
            return new AesKey {
                Key = rfc.GetBytes(256 / 8),
                IV = rfc.GetBytes(128 / 8)
            };
        }

        public static string Encrypt(in string data, in AesKey key) {
            return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(data), key).Span);
        }

        public static Memory<byte> Encrypt(in Memory<byte> blob, in AesKey key) {
            using Aes aes = Aes.Create();

            aes.Key = key.Key;
            if(key.IV.Any()) {
                aes.IV = key.IV;
            }

            using MemoryStream memstream = new();
            using CryptoStream crpstream = new(memstream, aes.CreateEncryptor(), CryptoStreamMode.Write);

            crpstream.Write(blob.Span);
            crpstream.Close();

            return memstream.ToArray();
        }

        public static string Decrypt(in string data, in AesKey key) {
            return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(data), key).Span);
        }
        public static Memory<byte> Decrypt(in Memory<byte> blob, in AesKey key) {
            using Aes aes = Aes.Create();

            aes.Key = key.Key;
            if(key.IV.Any()) {
                aes.IV = key.IV;
            }

            using MemoryStream memstream = new();
            using CryptoStream crpstream = new(memstream, aes.CreateDecryptor(), CryptoStreamMode.Write);

            crpstream.Write(blob.Span);
            crpstream.Close();

            return memstream.ToArray();
        }
    }
}