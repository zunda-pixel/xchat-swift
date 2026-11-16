import Crypto
import Testing

@testable import XChat

/// P-256 key derivation, ECIES, and ECDSA against the cross-binding vectors
/// and published behaviours.
struct ECIESTests {
  @Test func generateKeyPairHasBothKeySizes() throws {
    let pair = generateKeyPair()
    #expect(pair.publicKey.count == 65)
    #expect(pair.publicKey[0] == 0x04)
    #expect(pair.privateKey.count == 32)
    #expect(isValidPublicKey(pair.publicKey))
    #expect(try derivePublicKey(privateKey: pair.privateKey, purpose: .identity) == pair.publicKey)
  }

  /// Deriving public keys from the vectors' private keys reproduces the
  /// vectors' SEC1 public keys, so the encoding matches the reference.
  @Test func vectorPrivateKeysDeriveTheirPublicKeys() throws {
    #expect(
      try derivePublicKey(
        privateKey: TestVectors.bytes("identity_private_b64"), purpose: .identity)
        == TestVectors.bytes("identity_public_b64"))
    #expect(
      try derivePublicKey(
        privateKey: TestVectors.bytes("signing_private_b64"), purpose: .signing)
        == TestVectors.bytes("signing_public_b64"))
  }

  @Test(arguments: [0, 1, 16, 32, 64, 1000, 2000])
  func eciesRoundTripAndWireFormat(length: Int) throws {
    let pair = generateKeyPair()
    let full = (0..<2000).map { UInt8($0 % 251) }
    let plaintext = Array(full[0..<length])
    let ciphertext = try encryptWithPublicKey(publicKey: pair.publicKey, data: plaintext)
    #expect(ciphertext.count == 65 + length + 16, "length \(length)")
    #expect(ciphertext[0] == 0x04, "length \(length)")
    #expect(
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: ciphertext) == plaintext,
      "length \(length)")
  }

  /// A compressed SEC1 recipient key parses the same as its uncompressed
  /// form.
  @Test func compressedRecipientKey() throws {
    let pair = generateKeyPair()
    let compressed = Array(
      try P256.KeyAgreement.PublicKey(x963Representation: pair.publicKey)
        .compressedRepresentation)
    #expect(compressed.count == 33)
    #expect(isValidPublicKey(compressed))

    let ciphertext = try encryptWithPublicKey(publicKey: compressed, data: [1, 2, 3])
    #expect(
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: ciphertext) == [1, 2, 3])
  }

  @Test func wrongKeyRejected() throws {
    let first = generateKeyPair()
    let second = generateKeyPair()
    let ciphertext = try encryptWithPublicKey(publicKey: first.publicKey, data: [9, 9, 9])

    #expect(throws: PrimitiveError.authenticationFailed) {
      try decryptWithPrivateKey(privateKey: second.privateKey, data: ciphertext)
    }
  }

  @Test func tamperRejected() throws {
    let pair = generateKeyPair()
    let ciphertext = try encryptWithPublicKey(publicKey: pair.publicKey, data: [1, 2, 3])

    // The ciphertext body.
    var body = ciphertext
    body[70] ^= 0xFF
    #expect(throws: PrimitiveError.authenticationFailed) {
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: body)
    }

    // The authentication tag.
    var tag = ciphertext
    tag[tag.count - 1] ^= 1
    #expect(throws: PrimitiveError.authenticationFailed) {
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: tag)
    }

    // The ephemeral public key prefix, leaving no point.
    var prefix = ciphertext
    prefix[0] = 0x00
    #expect(throws: PrimitiveError.authenticationFailed) {
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: prefix)
    }
  }

  @Test(arguments: [0, 1, 64, 80])
  func shortDataRejected(length: Int) {
    let pair = generateKeyPair()
    #expect(throws: PrimitiveError.ciphertextTooShort) {
      try decryptWithPrivateKey(
        privateKey: pair.privateKey,
        data: [UInt8](repeating: 0, count: length))
    }
  }

  @Test(arguments: [32, 31])
  func invalidPrivateKeyRejected(length: Int) throws {
    let pair = generateKeyPair()
    let ciphertext = try encryptWithPublicKey(publicKey: pair.publicKey, data: [1])

    #expect(throws: XChatError.invalidInput(.privateKey(.identity))) {
      try decryptWithPrivateKey(
        privateKey: [UInt8](repeating: 0, count: length), data: ciphertext)
    }
  }

  @Test func invalidSigningPrivateKeyRejected() {
    #expect(throws: XChatError.invalidInput(.privateKey(.signing))) {
      try derivePublicKey(privateKey: [UInt8](repeating: 0, count: 32), purpose: .signing)
    }
  }

  @Test func invalidPublicKeyRejected() {
    // Structurally valid but off the curve.
    let offCurve = [0x04] + [UInt8](repeating: 0, count: 64)
    #expect(!isValidPublicKey(offCurve))
    #expect(throws: PrimitiveError.invalidPublicKey) {
      try encryptWithPublicKey(publicKey: offCurve, data: [1])
    }
    // Wrong length.
    #expect(!isValidPublicKey([UInt8](repeating: 1, count: 32)))
  }

  @Test func signVerifyRoundTrip() throws {
    let pair = generateKeyPair()
    let payload = Array("message to sign".utf8)

    let signature = try sign(privateKey: pair.privateKey, payload: payload)
    #expect(signature.count == 64)
    #expect(try verify(publicKey: pair.publicKey, signature: signature, payload: payload))
    #expect(
      try !verify(
        publicKey: pair.publicKey, signature: signature,
        payload: Array("different message".utf8)))

    let other = generateKeyPair()
    #expect(try !verify(publicKey: other.publicKey, signature: signature, payload: payload))
  }

  /// The vector's signature was made by the reference over `message_utf8`
  /// with the signing key.
  @Test func vectorSignatureVerifies() throws {
    let publicKey = TestVectors.bytes("signing_public_b64")
    let signature = TestVectors.bytes("signature_b64")
    let message = Array(TestVectors.string("message_utf8").utf8)

    #expect(try verify(publicKey: publicKey, signature: signature, payload: message))
    #expect(
      try !verify(
        publicKey: publicKey, signature: signature,
        payload: message + [UInt8(ascii: "!")]))

    let identityPublic = TestVectors.bytes("identity_public_b64")
    #expect(try !verify(publicKey: identityPublic, signature: signature, payload: message))
  }

  @Test(arguments: [0, 63, 65])
  func invalidSignatureLength(length: Int) throws {
    let pair = generateKeyPair()
    #expect(throws: PrimitiveError.malformedSignature) {
      try verify(
        publicKey: pair.publicKey,
        signature: [UInt8](repeating: 0, count: length),
        payload: [1])
    }
  }
}
