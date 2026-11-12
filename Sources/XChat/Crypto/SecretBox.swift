/// XSalsa20-Poly1305, the AEAD the chat protocol encrypts message payloads
/// with — NaCl's `crypto_secretbox`. Ported from the reference implementation
/// the wire format is frozen against: the Poly1305 one-time key is the first
/// 32 keystream bytes, encryption continues from keystream byte 32 with no
/// skip (one stream, NaCl-style), and the tag is unpadded Poly1305 over the
/// ciphertext alone, with no length block or associated data.
struct XSalsa20Poly1305: Sendable {
    /// Extended-nonce size.
    static let nonceSize = 24
    /// Poly1305 tag size.
    static let tagSize = 16

    private let key: [UInt8]

    init(key: [UInt8]) {
        precondition(key.count == 32, "XSalsa20Poly1305 keys are 32 bytes")
        self.key = key
    }

    /// Encrypts under a 24-byte extended nonce, returning the ciphertext
    /// and its detached tag.
    func encryptDetached(nonce: [UInt8], plaintext: [UInt8]) -> (ciphertext: [UInt8], tag: [UInt8]) {
        var cipher = Salsa20.xsalsa(key: key, nonce: nonce)
        let macKey = deriveMacKey(&cipher)
        var ciphertext = plaintext
        cipher.xor(into: &ciphertext)
        var mac = Poly1305(key: macKey)
        return (ciphertext, mac.computeUnpadded(ciphertext))
    }

    /// Verifies the detached tag over the ciphertext, and only then decrypts:
    /// an invalid tag never yields plaintext.
    func decryptDetached(nonce: [UInt8], ciphertext: [UInt8], tag: [UInt8]) throws -> [UInt8] {
        guard tag.count == Self.tagSize else {
            throw XChatError.decryption("XSalsa20Poly1305 tags are 16 bytes")
        }
        var cipher = Salsa20.xsalsa(key: key, nonce: nonce)
        let macKey = deriveMacKey(&cipher)
        var mac = Poly1305(key: macKey)
        let expected = mac.computeUnpadded(ciphertext)
        guard constantTimeEquals(expected, tag) else {
            throw XChatError.decryption("XSalsa20Poly1305 decryption failed")
        }
        var plaintext = ciphertext
        cipher.xor(into: &plaintext)
        return plaintext
    }

    /// Derives the one-time Poly1305 key from the first 32 keystream bytes,
    /// leaving the stream positioned where encryption begins.
    private func deriveMacKey(_ cipher: inout Salsa20) -> [UInt8] {
        var macKey = [UInt8](repeating: 0, count: 32)
        cipher.xor(into: &macKey)
        return macKey
    }
}

/// Encrypts a message payload with a fresh random nonce.
///
/// Wire format: nonce (24) || tag (16) || ciphertext.
func encryptMessage(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
    guard key.count == 32 else {
        throw XChatError.invalidInput("Invalid conversation key")
    }
    let cipher = XSalsa20Poly1305(key: key)
    var nonce = [UInt8](repeating: 0, count: XSalsa20Poly1305.nonceSize)
    for i in nonce.indices {
        nonce[i] = UInt8.random(in: 0...255)
    }
    let (ciphertext, tag) = cipher.encryptDetached(nonce: nonce, plaintext: plaintext)
    return nonce + tag + ciphertext
}

/// Decrypts a message payload in the wire format above.
func decryptMessage(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
    // Minimum size: nonce (24) + tag (16) = 40 bytes.
    guard ciphertext.count >= XSalsa20Poly1305.nonceSize + XSalsa20Poly1305.tagSize else {
        throw XChatError.decryption("Ciphertext too short")
    }
    guard key.count == 32 else {
        throw XChatError.invalidInput("Invalid conversation key")
    }
    let nonceSize = XSalsa20Poly1305.nonceSize
    let tagSize = XSalsa20Poly1305.tagSize
    let cipher = XSalsa20Poly1305(key: key)
    do {
        return try cipher.decryptDetached(
            nonce: Array(ciphertext[0..<nonceSize]),
            ciphertext: Array(ciphertext[(nonceSize + tagSize)...]),
            tag: Array(ciphertext[nonceSize..<nonceSize + tagSize]))
    } catch {
        throw XChatError.decryption("Decryption failed - invalid key or corrupted data")
    }
}
