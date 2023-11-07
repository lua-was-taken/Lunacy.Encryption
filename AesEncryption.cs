using Lunacy.Encryption.Extensions;
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
            //byte[] salt = RandomNumberGenerator.GetBytes(16);

            using Rfc2898DeriveBytes rfc = new(password, SHA256.HashData(iv.Span)[..16], iterations: 10000, HashAlgorithmName.SHA256);
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
            return Encrypt(Encoding.UTF8.GetBytes(data), key).ToHex();
        }

        public static Memory<byte> Encrypt(in Memory<byte> blob, in AesKey key) {
            using Aes aes = Aes.Create();

            aes.Key = key.Key;
            if(key.IV.Any()) {
                aes.IV = key.IV;
            }

            return aes.EncryptCbc(blob.Span, key.IV, PaddingMode.PKCS7);
        }

        public static string Decrypt(in string data, in AesKey key) {
            return Encoding.UTF8.GetString(Decrypt(data.GetBytesFromHex(), key).Span);
        }
        public static Memory<byte> Decrypt(in Memory<byte> blob, in AesKey key) {
            using Aes aes = Aes.Create();

            aes.Key = key.Key;
            if(key.IV.Any()) {
                aes.IV = key.IV;
            }

            return aes.DecryptCbc(blob.Span, key.IV, PaddingMode.PKCS7);
        }
    }
}