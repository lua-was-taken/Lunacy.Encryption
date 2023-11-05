namespace Lunacy.Encryption.Models {
    public class RSAKey {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }

        public RSAKey() : this(string.Empty, string.Empty) { }
        public RSAKey(string publicKey) : this(publicKey, string.Empty) { }
        public RSAKey(string publicKey, string privateKey) {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}