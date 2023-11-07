using Lunacy.Encryption.Exceptions;
using Lunacy.Encryption.Extensions;
using Lunacy.Encryption.Models;
using System.Security.Cryptography;
using System.Text;

namespace Lunacy.Encryption {
    public static class RSAEncryption {
        public static RSAKey GenerateKey() {
            using RSACryptoServiceProvider rsa = new();

            return new RSAKey {
                PublicKey = rsa.ExportRSAPublicKey().ToHex(),
                PrivateKey = rsa.ExportRSAPrivateKey().ToHex()
            };
        }

        public static string Encrypt(in string data, in RSAKey key) {
            return Encrypt(Encoding.UTF8.GetBytes(data), key).ToHex();
        }

        public static Memory<byte> Encrypt(in Memory<byte> blob, in RSAKey key) {
            if(string.IsNullOrWhiteSpace(key.PublicKey)) {
                throw new MissingPublicKeyException($"Provided {nameof(RSAKey)} instance contains invalid Xml public key.");
            }

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(key.PublicKey.GetBytesFromHex().Span, out _);

            return rsa.Encrypt(blob.Span, RSAEncryptionPadding.Pkcs1);
        }

        public static string Decrypt(in string data, in RSAKey key) {
            return Encoding.UTF8.GetString(Decrypt(data.GetBytesFromHex(), key).Span);
        }

        public static Memory<byte> Decrypt(in Memory<byte> blob, in RSAKey key) {
            if(string.IsNullOrWhiteSpace(key.PrivateKey)) {
                throw new MissingPublicKeyException($"Provided {nameof(RSAKey)} instance contains invalid Xml private key.");
            }

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(key.PrivateKey.GetBytesFromHex().Span, out _);

            return rsa.Decrypt(blob.Span, RSAEncryptionPadding.Pkcs1);
        }
    }
}