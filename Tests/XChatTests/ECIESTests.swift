import Crypto
import XCTest

@testable import XChat

/// P-256 key derivation, ECIES, and ECDSA against the cross-binding vectors
/// and published behaviours.
final class ECIESTests: XCTestCase {
  func testGenerateKeyPair() throws {
    let pair = generateKeyPair()
    XCTAssertEqual(pair.publicKey.count, 65)
    XCTAssertEqual(pair.publicKey[0], 0x04)
    XCTAssertEqual(pair.privateKey.count, 32)
    XCTAssertTrue(isValidPublicKey(pair.publicKey))
    XCTAssertEqual(try derivePublicKey(privateKey: pair.privateKey), pair.publicKey)
  }

  /// Deriving public keys from the vectors' private keys reproduces the
  /// vectors' SEC1 public keys, so the encoding matches the reference.
  func testVectorPrivateKeysDeriveTheirPublicKeys() throws {
    XCTAssertEqual(
      try derivePublicKey(privateKey: TestVectors.bytes("identity_private_b64")),
      TestVectors.bytes("identity_public_b64"))
    XCTAssertEqual(
      try derivePublicKey(privateKey: TestVectors.bytes("signing_private_b64")),
      TestVectors.bytes("signing_public_b64"))
  }

  func testECIESRoundTripAndWireFormat() throws {
    let pair = generateKeyPair()
    let full = (0..<2000).map { UInt8($0 % 251) }
    for length in [0, 1, 16, 32, 64, 1000, 2000] {
      let plaintext = Array(full[0..<length])
      let ciphertext = try encryptWithPublicKey(publicKey: pair.publicKey, data: plaintext)
      XCTAssertEqual(ciphertext.count, 65 + length + 16, "length \(length)")
      XCTAssertEqual(ciphertext[0], 0x04, "length \(length)")
      XCTAssertEqual(
        try decryptWithPrivateKey(privateKey: pair.privateKey, data: ciphertext),
        plaintext,
        "length \(length)")
    }
  }

  /// A compressed SEC1 recipient key parses the same as its uncompressed
  /// form.
  func testCompressedRecipientKey() throws {
    let pair = generateKeyPair()
    let compressed = Array(
      try P256.KeyAgreement.PublicKey(x963Representation: pair.publicKey)
        .compressedRepresentation)
    XCTAssertEqual(compressed.count, 33)
    XCTAssertTrue(isValidPublicKey(compressed))

    let ciphertext = try encryptWithPublicKey(publicKey: compressed, data: [1, 2, 3])
    XCTAssertEqual(
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: ciphertext), [1, 2, 3])
  }

  func testWrongKeyRejected() throws {
    let first = generateKeyPair()
    let second = generateKeyPair()
    let ciphertext = try encryptWithPublicKey(publicKey: first.publicKey, data: [9, 9, 9])

    XCTAssertThrowsError(
      try decryptWithPrivateKey(privateKey: second.privateKey, data: ciphertext)
    ) { error in
      let error = error as? XChatError
      XCTAssertEqual(error?.kind, .decryption)
      XCTAssertEqual(
        error?.message, "Decryption failed - invalid key or corrupted data")
    }
  }

  func testTamperRejected() throws {
    let pair = generateKeyPair()
    let ciphertext = try encryptWithPublicKey(publicKey: pair.publicKey, data: [1, 2, 3])

    // The ciphertext body.
    var body = ciphertext
    body[70] ^= 0xFF
    XCTAssertThrowsError(
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: body)
    ) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .decryption)
    }

    // The authentication tag.
    var tag = ciphertext
    tag[tag.count - 1] ^= 1
    XCTAssertThrowsError(
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: tag)
    ) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .decryption)
    }

    // The ephemeral public key prefix.
    var prefix = ciphertext
    prefix[0] = 0x00
    XCTAssertThrowsError(
      try decryptWithPrivateKey(privateKey: pair.privateKey, data: prefix)
    ) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
    }
  }

  func testShortDataRejected() {
    let pair = generateKeyPair()
    for length in [0, 1, 64, 80] {
      XCTAssertThrowsError(
        try decryptWithPrivateKey(
          privateKey: pair.privateKey,
          data: [UInt8](repeating: 0, count: length))
      ) { error in
        let error = error as? XChatError
        XCTAssertEqual(error?.kind, .decryption)
        XCTAssertEqual(error?.message, "Data too short")
      }
    }
  }

  func testInvalidPrivateKeyRejected() throws {
    let pair = generateKeyPair()
    let ciphertext = try encryptWithPublicKey(publicKey: pair.publicKey, data: [1])

    for key in [[UInt8](repeating: 0, count: 32), [UInt8](repeating: 0, count: 31)] {
      XCTAssertThrowsError(
        try decryptWithPrivateKey(privateKey: key, data: ciphertext)
      ) { error in
        XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
      }
    }
    XCTAssertThrowsError(try derivePublicKey(privateKey: [UInt8](repeating: 0, count: 32))) {
      error in
      XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
    }
  }

  func testInvalidPublicKeyRejected() {
    // Structurally valid but off the curve.
    let offCurve = [0x04] + [UInt8](repeating: 0, count: 64)
    XCTAssertFalse(isValidPublicKey(offCurve))
    XCTAssertThrowsError(try encryptWithPublicKey(publicKey: offCurve, data: [1])) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
    }
    // Wrong length.
    XCTAssertFalse(isValidPublicKey([UInt8](repeating: 1, count: 32)))
  }

  func testSignVerifyRoundTrip() throws {
    let pair = generateKeyPair()
    let payload = Array("message to sign".utf8)

    let signature = try sign(privateKey: pair.privateKey, payload: payload)
    XCTAssertEqual(signature.count, 64)
    XCTAssertTrue(try verify(publicKey: pair.publicKey, signature: signature, payload: payload))
    XCTAssertFalse(
      try verify(
        publicKey: pair.publicKey, signature: signature,
        payload: Array("different message".utf8)))

    let other = generateKeyPair()
    XCTAssertFalse(
      try verify(publicKey: other.publicKey, signature: signature, payload: payload))
  }

  /// The vector's signature was made by the reference over `message_utf8`
  /// with the signing key.
  func testVectorSignatureVerifies() throws {
    let publicKey = TestVectors.bytes("signing_public_b64")
    let signature = TestVectors.bytes("signature_b64")
    let message = Array(TestVectors.string("message_utf8").utf8)

    XCTAssertTrue(try verify(publicKey: publicKey, signature: signature, payload: message))
    XCTAssertFalse(
      try verify(
        publicKey: publicKey, signature: signature,
        payload: message + [UInt8(ascii: "!")]))

    let identityPublic = TestVectors.bytes("identity_public_b64")
    XCTAssertFalse(
      try verify(publicKey: identityPublic, signature: signature, payload: message))
  }

  func testInvalidSignatureLength() throws {
    let pair = generateKeyPair()
    for length in [0, 63, 65] {
      XCTAssertThrowsError(
        try verify(
          publicKey: pair.publicKey,
          signature: [UInt8](repeating: 0, count: length),
          payload: [1])
      ) { error in
        let error = error as? XChatError
        XCTAssertEqual(error?.kind, .verification)
        XCTAssertEqual(error?.message, "Invalid signature length")
      }
    }
  }
}
