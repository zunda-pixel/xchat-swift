/// What the cryptographic primitives throw when the bytes they are given do
/// not open or parse. A primitive does not know whose bytes they are (a
/// file's frame, a participant's public key, an event's signature), so the
/// SDK call that used it reports the failure as the `XChatError` that says
/// so, and none of these reaches a caller as is.
enum PrimitiveError: Error, Hashable {
  /// Ciphertext is shorter than its format's fixed overhead.
  case ciphertextTooShort
  /// Ciphertext did not authenticate: it is another key's, or corrupted.
  case authenticationFailed
  /// A secretstream frame authenticated but carries a tag the stream format
  /// does not define; the value is that tag.
  case unknownStreamTag(UInt8)
  /// A public key is not a P-256 point in compressed SEC1, uncompressed
  /// SEC1, or canonical SPKI DER.
  case invalidPublicKey
  /// A signature is not a raw 64-byte `r || s` ECDSA P-256 signature.
  case malformedSignature
}
