using Lunacy.Encryption.Extensions;
using Lunacy.Encryption.Models;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Lunacy.Encryption {
	public class PasswordCipher {
		public string Hash { get; set; } = string.Empty;
		public string Salt { get; set; } = string.Empty;

		public bool CompareTo(string plainText) {
			return DeriveFromPassword(plainText, Salt).Hash == Hash;
		}

		public static PasswordCipher DeriveFromPassword(string plainText) => DeriveFromPassword(plainText, CipherHelper.GenerateSalt());
		public static PasswordCipher DeriveFromPassword(string plainText, string salt) {
			Memory<byte> bSalt = salt.GetBytesFromHex();
			byte[] bIV = SHA256.HashData(bSalt.Span)[..16];

			AesKey key = AesEncryption.GenerateKeyFromPwd(plainText, bIV);

			return new PasswordCipher() {
				Hash = SHA256.HashData(plainText.AsBytes().EncryptAes(key).ToArray()).ToHex(),
				Salt = salt
			};
		}
	}
}