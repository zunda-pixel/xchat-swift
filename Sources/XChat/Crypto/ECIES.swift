import Crypto
import Foundation

/// The DER SubjectPublicKeyInfo encoding of an uncompressed SEC1 P-256
/// public key. Registration uploads this form, and the identity-key binding
/// signatures are over it.
func spkiDER(publicKey: [UInt8]) throws -> [UInt8] {
  Array(try parsePublicKey(publicKey).derRepresentation)
}

/// Generates a P-256 keypair: a 65-byte uncompressed public key
/// (`0x04 || x || y`) and a 32-byte private scalar. Identity and signing
/// keys are the same kind of key; the purpose is metadata the SDK records.
func generateKeyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
  let key = P256.KeyAgreement.PrivateKey()
  return (Array(key.publicKey.x963Representation), Array(key.rawRepresentation))
}

/// Parses a P-256 public key in compressed SEC1, uncompressed SEC1, or SPKI
/// DER, throwing `PrimitiveError.invalidPublicKey` for anything else.
func parsePublicKey(_ bytes: [UInt8]) throws -> P256.KeyAgreement.PublicKey {
  let key: P256.KeyAgreement.PublicKey
  do {
    switch bytes.count {
    case 33:
      return try P256.KeyAgreement.PublicKey(compressedRepresentation: bytes)
    case 65:
      return try P256.KeyAgreement.PublicKey(x963Representation: bytes)
    default:
      key = try P256.KeyAgreement.PublicKey(derRepresentation: bytes)
    }
  } catch {
    throw PrimitiveError.invalidPublicKey
  }

  // Swift Crypto can decode a point without checking that its SPKI algorithm
  // identifier names P-256. Require the canonical P-256 encoding used by X.
  guard key.derRepresentation.elementsEqual(bytes) else {
    throw PrimitiveError.invalidPublicKey
  }
  return key
}

/// Whether `bytes` encode a valid P-256 public key.
func isValidPublicKey(_ bytes: [UInt8]) -> Bool {
  (try? parsePublicKey(bytes)) != nil
}

/// Parses a 32-byte P-256 private scalar in `[1, n-1]`. `purpose` says
/// which of this device's keys the bytes are, which the error names.
func parsePrivateKey(
  _ bytes: [UInt8], purpose: XChatError.KeyPurpose
) throws -> P256.KeyAgreement.PrivateKey {
  do {
    return try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes)
  } catch {
    throw XChatError.invalidInput(.privateKey(purpose))
  }
}

/// Derives a private key's SEC1 uncompressed public key (65 bytes).
func derivePublicKey(
  privateKey: [UInt8], purpose: XChatError.KeyPurpose
) throws -> [UInt8] {
  let key = try parsePrivateKey(privateKey, purpose: purpose)
  return Array(key.publicKey.x963Representation)
}

/// Encrypts `data` to a P-256 public key using ECIES: an ephemeral ECDH
/// exchange, X9.63 KDF2 with the ephemeral public key as shared info, and
/// AES-128-GCM under the derived key and 16-byte IV.
///
/// Wire format: ephemeral public key (65) || ciphertext || tag (16).
func encryptWithPublicKey(publicKey: [UInt8], data: [UInt8]) throws -> [UInt8] {
  let recipient = try parsePublicKey(publicKey)

  // A fresh ephemeral key on every call, so the derived IV never repeats.
  let ephemeral = P256.KeyAgreement.PrivateKey()
  let ephemeralPublicBytes = Array(ephemeral.publicKey.x963Representation)
  let shared: SharedSecret
  do {
    shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
  } catch {
    throw XChatError.internalError(.keyAgreementFailed)
  }

  let material = shared.x963DerivedSymmetricKey(
    using: SHA256.self, sharedInfo: ephemeralPublicBytes, outputByteCount: 32)
  let derived = unsafe material.withUnsafeBytes { unsafe Array($0) }
  let cipher = AES128GCM(key: Array(derived[0..<16]))
  let sealed = try cipher.seal(nonce: Array(derived[16..<32]), plaintext: data)
  return ephemeralPublicBytes + sealed
}

/// Decrypts data produced by `encryptWithPublicKey` for the given 32-byte
/// private key.
func decryptWithPrivateKey(privateKey: [UInt8], data: [UInt8]) throws -> [UInt8] {
  // Minimum size: ephemeral public key (65) + tag (16).
  guard data.count >= 81 else {
    throw PrimitiveError.ciphertextTooShort
  }

  let ephemeralPublicBytes = Array(data[0..<65])
  let ephemeral: P256.KeyAgreement.PublicKey
  do {
    ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicBytes)
  } catch {
    // Corrupting the ephemeral key's bytes either leaves no point, as here,
    // or another point, whose shared secret fails the tag; both are
    // ciphertext that does not open.
    throw PrimitiveError.authenticationFailed
  }
  // Conversation keys are encrypted to the identity key.
  let secret = try parsePrivateKey(privateKey, purpose: .identity)
  let shared: SharedSecret
  do {
    shared = try secret.sharedSecretFromKeyAgreement(with: ephemeral)
  } catch {
    throw XChatError.internalError(.keyAgreementFailed)
  }

  let material = shared.x963DerivedSymmetricKey(
    using: SHA256.self, sharedInfo: ephemeralPublicBytes, outputByteCount: 32)
  let derived = unsafe material.withUnsafeBytes { unsafe Array($0) }
  let cipher = AES128GCM(key: Array(derived[0..<16]))
  return try cipher.open(nonce: Array(derived[16..<32]), ciphertextAndTag: Array(data[65...]))
}

/// Signs `payload` with ECDSA P-256 over SHA-256, returning the raw 64-byte
/// `r || s` signature. The key is one `importKeys` or `generateKeypairs`
/// already accepted, so a failure is the SDK's.
func sign(privateKey: [UInt8], payload: [UInt8]) throws -> [UInt8] {
  do {
    let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
    return Array(try key.signature(for: Data(payload)).rawRepresentation)
  } catch {
    throw XChatError.internalError(.signingFailed)
  }
}

/// Verifies a raw 64-byte `r || s` ECDSA P-256 SHA-256 signature. Returns
/// false for a signature that does not match; throws only when the public
/// key (`PrimitiveError.invalidPublicKey`) or the signature
/// (`PrimitiveError.malformedSignature`) is malformed.
func verify(publicKey: [UInt8], signature: [UInt8], payload: [UInt8]) throws -> Bool {
  guard signature.count == 64 else {
    throw PrimitiveError.malformedSignature
  }
  let publicPoint = try parsePublicKey(publicKey)
  let key: P256.Signing.PublicKey
  do {
    key = try P256.Signing.PublicKey(x963Representation: publicPoint.x963Representation)
  } catch {
    throw PrimitiveError.invalidPublicKey
  }
  let parsed: P256.Signing.ECDSASignature
  do {
    parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
  } catch {
    throw PrimitiveError.malformedSignature
  }
  return key.isValidSignature(parsed, for: Data(payload))
}
