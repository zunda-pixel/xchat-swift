/// Public key registration, as the X API's registration request carries it.
public struct PublicKeyRegistrationPayload: Sendable, Equatable {
  public var publicKey: PublicKeyRegistration
}

public struct PublicKeyRegistration: Sendable, Equatable {
  /// Base64 raw `r || s` signature of the identity key's SPKI DER by the
  /// **signing** private key.
  public var identityPublicKeySignature: String
  /// Base64 SPKI DER identity public key.
  public var publicKey: String
  /// URL-safe base64 SHA-256 of the identity key's SPKI DER.
  public var publicKeyFingerprint: String?
  public var registrationMethod: String
  /// Base64 SPKI DER signing public key.
  public var signingPublicKey: String
  /// Base64 raw `r || s` signature of the signing key's SPKI DER by the
  /// **identity** private key: the other half of the binding.
  public var signingPublicKeySignature: String?
}

/// The loaded identity and signing public keys, as base64 SEC1 points.
public struct PublicKeys: Sendable, Equatable {
  public var identity: String
  public var signing: String
}
