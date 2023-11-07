using Lunacy.Encryption.Extensions;

namespace Lunacy.Encryption {
    public static class CipherHelper {
        public static string GenerateSalt(uint length = 8) {
            if(length % 2 != 0) {
                throw new ArgumentException("Salt length must be a multiple of 2", nameof(length));
            }

            byte[] buffer = new byte[length / 2];
            Random.Shared.NextBytes(buffer);

            return buffer.ToHex();
        }
    }
}