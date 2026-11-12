import Crypto

/// SHA-256 of `data`.
func sha256(_ data: [UInt8]) -> [UInt8] {
    Array(SHA256.hash(data: data))
}

/// HMAC-SHA256 of `message` under `key`.
func hmacSHA256(message: [UInt8], key: [UInt8]) -> [UInt8] {
    let code = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
    return Array(code)
}

/// HKDF-SHA256 (RFC 5869) with a string salt; an empty salt expands to 32
/// zero bytes. `hkdf` is this with an empty `info`.
func hkdf(secret: [UInt8], salt: String, length: Int) throws -> [UInt8] {
    try hkdfWithInfo(secret: secret, salt: salt, info: [], length: length)
}

/// HKDF-SHA256 with an `info` input, which domain-separates keys derived
/// from the same secret and salt with different purposes.
func hkdfWithInfo(secret: [UInt8], salt: String, info: [UInt8], length: Int) throws -> [UInt8] {
    // Maximum output length per the HKDF spec: 255 blocks of 32 bytes.
    let maximumLength = 32 * 255
    guard length <= maximumLength else {
        throw XChatError.internalError(
            "Requested length \(length) exceeds maximum \(maximumLength)")
    }

    // An empty salt expands to 32 zero bytes.
    let saltBytes = salt.isEmpty ? [UInt8](repeating: 0, count: 32) : Array(salt.utf8)

    let derived = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: secret),
        salt: saltBytes,
        info: info,
        outputByteCount: length)
    return unsafe derived.withUnsafeBytes { unsafe Array($0) }
}

/// Cryptographically secure random bytes, from the system random source.
func randomBytes(_ length: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: length)
    for index in bytes.indices {
        bytes[index] = UInt8.random(in: 0...255)
    }
    return bytes
}
