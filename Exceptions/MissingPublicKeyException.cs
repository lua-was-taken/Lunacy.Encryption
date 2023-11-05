namespace Lunacy.Encryption.Exceptions {
    public sealed class MissingPublicKeyException : Exception {
        public MissingPublicKeyException(string message) : base(message) { }
    }
}
