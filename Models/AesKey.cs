namespace Lunacy.Encryption.Models {
    public class AesKey {
        public string KeyBase64 => Convert.ToBase64String(Key);
        public string IVBase64 => Convert.ToBase64String(IV);

        public byte[] Key { get; set; }
        public byte[] IV { get; set; }

        public AesKey() : this(Array.Empty<byte>(), Array.Empty<byte>()) { }
        public AesKey(byte[] key, byte[] iv) {
            Key = key;
            IV = iv;
        }
    }
}