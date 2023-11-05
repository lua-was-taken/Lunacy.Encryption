using Lunacy.Encryption.Models;
using System.Text;

namespace Lunacy.Encryption.Extensions {
    public static class StringExtensions {
        public static Memory<byte> AsBytes(this string value) {
            return Encoding.UTF8.GetBytes(value);
        }

        public static Memory<byte> GetBytesFromHex(this string value) {
            byte[] bytes = new byte[value.Length / 2];

            for(int i = 0; i < value.Length; i += 2) {
                bytes[i / 2] = Convert.ToByte(value.Substring(i, 2), 16);
            }

            return bytes;
        }

        public static string EncryptAes(this string value, in AesKey key) {
            return AesEncryption.Encrypt(value, key);
        }

        public static string EncryptRsa(this string value, in RSAKey key) {
            return RSAEncryption.Encrypt(value, key);
        }

        public static string DecryptAes(this string value, in AesKey key) {
            return AesEncryption.Decrypt(value, key);
        }

        public static string DecryptRsa(this string value, in RSAKey key) {
            return RSAEncryption.Decrypt(value, key);
        }
    }
}