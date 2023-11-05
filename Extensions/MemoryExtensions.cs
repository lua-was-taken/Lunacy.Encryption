using Lunacy.Encryption.Models;
using System.Text;

namespace Lunacy.Encryption.Extensions {
    public static class MemoryExtensions {
        public static string AsString(this byte[] bytes) => AsString((Memory<byte>)bytes);
        public static string AsString(this Memory<byte> memory) {
            return Encoding.UTF8.GetString(memory.Span);
        }

        public static string ToHex(this byte[] bytes) => ToHex((Memory<byte>)bytes);
        public static string ToHex(this Memory<byte> memory) {
            StringBuilder builder = new(memory.Length * 2);
            foreach(byte value in memory.Span) {
                builder.AppendFormat("{0:x2}", value);
            }

            return builder.ToString();
        }

        public static Memory<byte> EncryptAes(this byte[] bytes, in AesKey key) => EncryptAes((Memory<byte>)bytes, key);
        public static Memory<byte> EncryptAes(this Memory<byte> memory, in AesKey key) {
            return AesEncryption.Encrypt(memory, key);
        }

        public static Memory<byte> EncryptRSA(this byte[] bytes, in RSAKey key) => EncryptRSA((Memory<byte>)bytes, key);
        public static Memory<byte> EncryptRSA(this Memory<byte> memory, in RSAKey key) {
            return RSAEncryption.Encrypt(memory, key);
        }

        public static Memory<byte> DecryptAes(this byte[] bytes, in AesKey key) => DecryptAes((Memory<byte>)bytes, key);
        public static Memory<byte> DecryptAes(this Memory<byte> memory, in AesKey key) {
            return AesEncryption.Decrypt(memory, key);
        }

        public static Memory<byte> DecryptRSA(this byte[] bytes, in RSAKey key) => DecryptRSA((Memory<byte>)bytes, key);
        public static Memory<byte> DecryptRSA(this Memory<byte> memory, in RSAKey key) {
            return RSAEncryption.Decrypt(memory, key);
        }
    }
}