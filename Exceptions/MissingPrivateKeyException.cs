namespace Lunacy.Encryption.Exceptions {
    public sealed class MissingPrivateKeyException : Exception {
        public MissingPrivateKeyException(string message) : base(message) { }
    }
}