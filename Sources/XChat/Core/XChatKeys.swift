extension XChatCore {
  // MARK: Registration

  /// Generates new identity and signing keypairs, loads them, and returns
  /// the registration payload for the X API.
  ///
  /// No key version is set: after registering, pass the version the API
  /// returns to `setPublicKeyVersion` (or to `importKeys` on a later
  /// launch).
  public func generateKeypairs() throws -> PublicKeyRegistrationPayload {
    let identity = generateKeyPair()
    let signing = generateKeyPair()

    let identitySPKI = try spkiDER(publicKey: identity.publicKey)
    let signingSPKI = try spkiDER(publicKey: signing.publicKey)
    // The signing key endorses the identity key, and the identity key
    // endorses the signing key: the two-way binding registration stores.
    let identitySignature = try sign(
      privateKey: signing.privateKey, payload: identitySPKI)
    let signingSignature = try sign(
      privateKey: identity.privateKey, payload: signingSPKI)

    identityPrivateKey = identity.privateKey
    signingPrivateKey = signing.privateKey
    keyVersion = nil

    return PublicKeyRegistrationPayload(
      publicKey: PublicKeyRegistration(
        identityPublicKeySignature: Base64.encodeStandardPadded(identitySignature),
        publicKey: Base64.encodeStandardPadded(identitySPKI),
        publicKeyFingerprint: fingerprint(spki: identitySPKI),
        registrationMethod: "CustomPin",
        signingPublicKey: Base64.encodeStandardPadded(signingSPKI),
        signingPublicKeySignature: Base64.encodeStandardPadded(signingSignature)))
  }

  /// The loaded identity and signing public keys, base64 SEC1.
  public func getPublicKeys() throws -> PublicKeys {
    guard let identityPrivateKey else {
      throw XChatError.invalidState("keys are not loaded: import keys first")
    }
    guard let signingPrivateKey else {
      throw XChatError.invalidState("signing key is not loaded")
    }
    return PublicKeys(
      identity: Base64.encodeStandardPadded(
        try derivePublicKey(privateKey: identityPrivateKey)),
      signing: Base64.encodeStandardPadded(
        try derivePublicKey(privateKey: signingPrivateKey)))
  }

  /// The loaded identity key's fingerprint: URL-safe base64 SHA-256 of its
  /// SPKI DER, which users compare out of band.
  public func getPublicKeyFingerprint() throws -> String {
    guard let identityPrivateKey else {
      throw XChatError.invalidState("keys are not loaded: import keys first")
    }
    let publicKey = try derivePublicKey(privateKey: identityPrivateKey)
    return fingerprint(spki: try spkiDER(publicKey: publicKey))
  }

  /// Sets the version the loaded keys were registered under, which signs
  /// with them and selects this device's participant key in key changes.
  public func setPublicKeyVersion(_ version: String) throws {
    try validatePublicKeyVersion(version)
    keyVersion = version
  }

  func validatePublicKeyVersion(_ version: String) throws {
    let canonical = Int64(version).map(String.init)
    guard canonical == version, let number = Int64(version), number >= 0 else {
      throw XChatError.invalidInput(
        "Invalid public key version '\(version)': pass the key version as the X API "
          + "returns it, an integer in digits")
    }
  }

  private func fingerprint(spki: [UInt8]) -> String {
    Base64.encodeURLSafe(sha256(spki))
  }
}
