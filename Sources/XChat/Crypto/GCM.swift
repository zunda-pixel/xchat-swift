/// AES-128-GCM.
///
/// The protocol instantiates GCM with a 16-byte nonce (the ECIES layout),
/// where the pre-counter block J0 is GHASH of the IV rather than the
/// IV‖0^31‖1 form used for 96-bit IVs. Both lengths are supported here, per
/// NIST SP 800-38D.
struct AES128GCM: Sendable {
    private let aes: AES128
    private let h: [UInt8]

    init(key: [UInt8]) {
        aes = AES128(key: key)
        h = aes.encryptBlock([UInt8](repeating: 0, count: 16))
    }

    /// Encrypts and authenticates. Returns `ciphertext || tag` (tag last).
    func seal(nonce: [UInt8], plaintext: [UInt8], authenticatedData: [UInt8] = []) -> [UInt8] {
        let j0 = preCounterBlock(nonce: nonce)
        var ciphertext = ctr(j0: j0, input: plaintext)
        let tag = tag(j0: j0, authenticatedData: authenticatedData, ciphertext: ciphertext)
        ciphertext.append(contentsOf: tag)
        return ciphertext
    }

    /// Verifies the tag then decrypts. Input is `ciphertext || tag`.
    func open(nonce: [UInt8], ciphertextAndTag: [UInt8], authenticatedData: [UInt8] = []) throws -> [UInt8] {
        guard ciphertextAndTag.count >= 16 else {
            throw XChatError.decryption("Ciphertext too short")
        }
        let tagStart = ciphertextAndTag.count - 16
        let ct = [UInt8](ciphertextAndTag[0 ..< tagStart])
        let tag = [UInt8](ciphertextAndTag[tagStart...])
        let j0 = preCounterBlock(nonce: nonce)
        let expected = self.tag(j0: j0, authenticatedData: authenticatedData, ciphertext: ct)
        guard constantTimeEquals(expected, tag) else {
            throw XChatError.decryption("Failed to decrypt conversation key")
        }
        return ctr(j0: j0, input: ct)
    }

    // MARK: - Internals

    /// J0: the counter block the tag is computed from and the CTR stream
    /// is incremented from.
    private func preCounterBlock(nonce: [UInt8]) -> [UInt8] {
        if nonce.count == 12 {
            var j0 = nonce
            j0.append(contentsOf: [0, 0, 0, 0])
            j0[15] = 1
            return j0
        }
        // Non-96-bit IV: J0 = GHASH(IV ‖ pad ‖ 64-bit BE bit length of IV).
        var input = nonce
        input.append(contentsOf: [UInt8](repeating: 0, count: (16 - nonce.count % 16) % 16))
        var length = [UInt8](repeating: 0, count: 16)
        let bits = UInt64(nonce.count) * 8
        for i in 0..<8 { length[8 + i] = UInt8(truncatingIfNeeded: bits >> (8 * UInt64(7 - i))) }
        input.append(contentsOf: length)
        var j0 = [UInt8](repeating: 0, count: 16)
        var offset = 0
        while offset < input.count {
            for i in 0..<16 { j0[i] ^= input[offset + i] }
            j0 = Self.multiply(j0, h)
            offset += 16
        }
        return j0
    }

    /// CTR mode: the i-th plaintext block is XORed with E_K(inc32^i(J0)).
    private func ctr(j0: [UInt8], input: [UInt8]) -> [UInt8] {
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        var counter = j0
        var offset = 0
        while offset < input.count {
            increment32(&counter)
            let keystream = aes.encryptBlock(counter)
            let chunk = Swift.min(16, input.count - offset)
            for i in 0..<chunk { output.append(input[offset + i] ^ keystream[i]) }
            offset += chunk
        }
        return output
    }

    /// GHASH over AAD and ciphertext with the length block, then the tag
    /// E_K(J0) XOR S. Partial trailing blocks are zero-padded.
    private func tag(j0: [UInt8], authenticatedData: [UInt8], ciphertext: [UInt8]) -> [UInt8] {
        var y = [UInt8](repeating: 0, count: 16)
        for region in [authenticatedData, ciphertext] {
            var offset = 0
            while offset < region.count {
                let chunk = Swift.min(16, region.count - offset)
                for i in 0..<chunk { y[i] ^= region[offset + i] }
                y = Self.multiply(y, h)
                offset += 16
            }
        }
        // Trailing zeros of the last partial block, then the bit lengths.
        var lengthBlock = [UInt8](repeating: 0, count: 16)
        let aadBits = UInt64(authenticatedData.count) * 8
        let ctBits = UInt64(ciphertext.count) * 8
        for i in 0..<8 { lengthBlock[i] = UInt8(truncatingIfNeeded: aadBits >> (8 * UInt64(7 - i))) }
        for i in 0..<8 { lengthBlock[8 + i] = UInt8(truncatingIfNeeded: ctBits >> (8 * UInt64(7 - i))) }
        for i in 0..<16 { y[i] ^= lengthBlock[i] }
        y = Self.multiply(y, h)

        let ej0 = aes.encryptBlock(j0)
        for i in 0..<16 { y[i] ^= ej0[i] }
        return y
    }

    /// Big-endian increment of the last 32 bits of the counter block.
    private func increment32(_ block: inout [UInt8]) {
        for i in (12..<16).reversed() {
            block[i] = block[i] &+ 1
            if block[i] != 0 { break }
        }
    }

    /// Multiplication in GF(2^128) with the GCM polynomial, following
    /// NIST SP 800-38D algorithm 1: bits are counted from the most
    /// significant, V is shifted right with R = 0xE1‖0^7 fed back when its
    /// low bit was set.
    static func multiply(_ x: [UInt8], _ y: [UInt8]) -> [UInt8] {
        var z = [UInt8](repeating: 0, count: 16)
        var v = y
        for i in 0..<128 {
            let byte = x[i / 8]
            if byte & (1 << UInt8(7 - i % 8)) != 0 {
                for j in 0..<16 { z[j] ^= v[j] }
            }
            let lsb = v[15] & 1
            for j in (1..<16).reversed() { v[j] = v[j] >> 1 | v[j - 1] << 7 }
            v[0] >>= 1
            if lsb == 1 { v[0] ^= 0xe1 }
        }
        return z
    }
}

/// Constant-time 16-byte tag comparison.
func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in a.indices { diff |= a[i] ^ b[i] }
    return diff == 0
}
