import Crypto
import Foundation

/// The DER SubjectPublicKeyInfo encoding of an uncompressed SEC1 P-256
/// public key. Registration uploads this form, and the identity-key binding
/// signatures are over it.
func spkiDER(publicKey: [UInt8]) -> [UInt8] {
    precondition(publicKey.count == 65, "SPKI encoding takes an uncompressed P-256 key")
    let header: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]
    return header + publicKey
}

/// Generates a P-256 keypair: a 65-byte uncompressed public key
/// (`0x04 || x || y`) and a 32-byte private scalar. Identity and signing
/// keys are the same kind of key; the purpose is metadata the SDK records.
func generateKeyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
    let key = P256.KeyAgreement.PrivateKey()
    return (Array(key.publicKey.x963Representation), Array(key.rawRepresentation))
}

/// Parses a SEC1 P-256 public key: 33-byte compressed or 65-byte
/// uncompressed. Off-curve points are rejected.
func parsePublicKey(_ bytes: [UInt8]) throws -> P256.KeyAgreement.PublicKey {
    do {
        if bytes.count == 33 {
            return try P256.KeyAgreement.PublicKey(compressedRepresentation: bytes)
        }
        return try P256.KeyAgreement.PublicKey(x963Representation: bytes)
    } catch {
        throw XChatError.invalidInput("Invalid public key: \(error)")
    }
}

/// Whether `bytes` encode a valid P-256 point in either SEC1 form.
func isValidPublicKey(_ bytes: [UInt8]) -> Bool {
    (try? parsePublicKey(bytes)) != nil
}

/// Parses a 32-byte P-256 private scalar in `[1, n-1]`.
func parsePrivateKey(_ bytes: [UInt8]) throws -> P256.KeyAgreement.PrivateKey {
    do {
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes)
    } catch {
        throw XChatError.invalidInput("Invalid private key: \(error)")
    }
}

/// Derives a private key's SEC1 uncompressed public key (65 bytes).
func derivePublicKey(privateKey: [UInt8]) throws -> [UInt8] {
    let key = try parsePrivateKey(privateKey)
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
    let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)

    let derived = kdf2SHA256(
        sharedSecret: unsafe shared.withUnsafeBytes { unsafe Array($0) },
        sharedInfo: ephemeralPublicBytes,
        length: 32)
    let cipher = AES128GCM(key: Array(derived[0..<16]))
    let sealed = cipher.seal(nonce: Array(derived[16..<32]), plaintext: data)
    return ephemeralPublicBytes + sealed
}

/// Decrypts data produced by `encryptWithPublicKey` for the given 32-byte
/// private key.
func decryptWithPrivateKey(privateKey: [UInt8], data: [UInt8]) throws -> [UInt8] {
    // Minimum size: ephemeral public key (65) + tag (16).
    guard data.count >= 81 else {
        throw XChatError.decryption("Data too short")
    }

    let ephemeralPublicBytes = Array(data[0..<65])
    let ephemeral: P256.KeyAgreement.PublicKey
    do {
        ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicBytes)
    } catch {
        throw XChatError.invalidInput("Invalid ephemeral public key: \(error)")
    }
    let secret = try parsePrivateKey(privateKey)
    let shared = try secret.sharedSecretFromKeyAgreement(with: ephemeral)

    let derived = kdf2SHA256(
        sharedSecret: unsafe shared.withUnsafeBytes { unsafe Array($0) },
        sharedInfo: ephemeralPublicBytes,
        length: 32)
    let cipher = AES128GCM(key: Array(derived[0..<16]))
    do {
        return try cipher.open(
            nonce: Array(derived[16..<32]), ciphertextAndTag: Array(data[65...]))
    } catch {
        throw XChatError.decryption("Decryption failed - invalid key or corrupted data")
    }
}

/// Signs `payload` with ECDSA P-256 over SHA-256, returning the raw 64-byte
/// `r || s` signature.
func sign(privateKey: [UInt8], payload: [UInt8]) throws -> [UInt8] {
    let key: P256.Signing.PrivateKey
    do {
        key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
    } catch {
        throw XChatError.internalError("Invalid signing key: \(error)")
    }
    let signature = try key.signature(for: Data(payload))
    return Array(signature.rawRepresentation)
}

/// Verifies a raw 64-byte `r || s` ECDSA P-256 SHA-256 signature. Returns
/// false for a signature that does not match; throws only when the public
/// key or signature is malformed.
func verify(publicKey: [UInt8], signature: [UInt8], payload: [UInt8]) throws -> Bool {
    guard signature.count == 64 else {
        throw XChatError.verification("Invalid signature length")
    }
    let key: P256.Signing.PublicKey
    do {
        // Registration uploads SPKI DER, whose 65-byte point follows a
        // 26-byte header; signed payloads name SEC1 points.
        let rawKey = publicKey.count == 91 ? Array(publicKey[26...]) : publicKey
        if rawKey.count == 33 {
            key = try P256.Signing.PublicKey(compressedRepresentation: rawKey)
        } else {
            key = try P256.Signing.PublicKey(x963Representation: rawKey)
        }
    } catch {
        throw XChatError.invalidInput("Invalid public key: \(error)")
    }
    let parsed: P256.Signing.ECDSASignature
    do {
        parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
    } catch {
        throw XChatError.verification("Invalid signature: \(error)")
    }
    return key.isValidSignature(parsed, for: Data(payload))
}
