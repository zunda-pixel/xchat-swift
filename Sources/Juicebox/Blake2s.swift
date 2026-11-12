/// BLAKE2s-256 (RFC 7693), the hash the Juicebox realm channel
/// (`Noise_NK_25519_ChaChaPoly_BLAKE2s`) is built on.
struct Blake2s {
    private static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]

    /// The ten message-word permutations, one per round.
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt32]
    private var buffer: [UInt8] = []
    private let outputLength: Int

    init(outputLength: Int = 32, key: [UInt8] = []) {
        precondition(outputLength >= 1 && outputLength <= 32, "BLAKE2s output is 1...32 bytes")
        precondition(key.count <= 32, "BLAKE2s keys are at most 32 bytes")
        self.outputLength = outputLength
        var state = Self.iv
        state[0] ^= 0x0101_0000 ^ UInt32(outputLength)
        // Keyed hashing sets the key length in the parameter block and hashes
        // the key, padded to a block, before the message.
        state[0] ^= UInt32(key.count) << 8
        h = state
        if !key.isEmpty {
            buffer.append(contentsOf: key)
            buffer.append(contentsOf: [UInt8](repeating: 0, count: 64 - key.count))
        }
    }

    mutating func update(_ data: [UInt8]) {
        buffer.append(contentsOf: data)
    }

    mutating func finalize() -> [UInt8] {
        let byteCount = UInt64(buffer.count)
        var fullBlocks = buffer.count / 64
        // An exact multiple of the block size still has a final block.
        if buffer.count % 64 == 0, buffer.count > 0 {
            fullBlocks -= 1
        }
        var offset = 0
        for _ in 0..<fullBlocks {
            compress(Array(buffer[offset..<offset + 64]), last: false, counted: UInt64(offset + 64))
            offset += 64
        }
        var last = Array(buffer[offset...])
        if last.count < 64 {
            last.append(contentsOf: [UInt8](repeating: 0, count: 64 - last.count))
        }
        compress(last, last: true, counted: byteCount)

        var out: [UInt8] = []
        out.reserveCapacity(32)
        for word in h { out.append(contentsOf: word.leBytes) }
        return Array(out.prefix(outputLength))
    }

    static func hash(_ data: [UInt8], outputLength: Int = 32) -> [UInt8] {
        var hasher = Blake2s(outputLength: outputLength)
        hasher.update(data)
        return hasher.finalize()
    }

    /// Keyed BLAKE2s, the MAC Juicebox derives unlock keys and commitments
    /// with.
    static func mac(key: [UInt8], message: [UInt8], outputLength: Int = 32) -> [UInt8] {
        var hasher = Blake2s(outputLength: outputLength, key: key)
        hasher.update(message)
        return hasher.finalize()
    }

    private mutating func compress(_ block: [UInt8], last: Bool, counted: UInt64) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(block[i * 4])
                | UInt32(block[i * 4 + 1]) << 8
                | UInt32(block[i * 4 + 2]) << 16
                | UInt32(block[i * 4 + 3]) << 24
        }
        var v = h + Self.iv
        v[12] ^= UInt32(truncatingIfNeeded: counted)
        v[13] ^= UInt32(truncatingIfNeeded: counted >> 32)
        if last { v[14] = ~v[14] }

        for round in 0..<10 {
            let s = Self.sigma[round]
            Self.mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            Self.mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            Self.mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            Self.mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            Self.mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            Self.mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            Self.mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            Self.mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i + 8]
        }
    }

    private static func mix(
        _ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32
    ) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotatedRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(12)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotatedRight(8)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(7)
    }
}

/// HMAC-BLAKE2s-256 (RFC 2104 over BLAKE2s), which Noise's key derivation
/// uses.
func hmacBlake2s(key: [UInt8], message: [UInt8]) -> [UInt8] {
    var paddedKey = key.count > 64 ? Blake2s.hash(key) : key
    if paddedKey.count < 64 {
        paddedKey.append(contentsOf: [UInt8](repeating: 0, count: 64 - paddedKey.count))
    }
    let inner = paddedKey.map { $0 ^ 0x36 }
    let outer = paddedKey.map { $0 ^ 0x5c }
    return Blake2s.hash(outer + Blake2s.hash(inner + message))
}

/// HKDF with HMAC-BLAKE2s, as Noise instantiates it: extract with the
/// chaining key as salt, then expand without info.
func hkdfBlake2s(salt: [UInt8], ikm: [UInt8], length: Int) -> [UInt8] {
    let prk = hmacBlake2s(key: salt, message: ikm)
    var output: [UInt8] = []
    var previous: [UInt8] = []
    var counter: UInt8 = 1
    while output.count < length {
        previous = hmacBlake2s(key: prk, message: previous + [counter])
        output.append(contentsOf: previous)
        counter &+= 1
    }
    return Array(output.prefix(length))
}

extension UInt32 {
    var leBytes: [UInt8] {
        [
            UInt8(truncatingIfNeeded: self),
            UInt8(truncatingIfNeeded: self >> 8),
            UInt8(truncatingIfNeeded: self >> 16),
            UInt8(truncatingIfNeeded: self >> 24),
        ]
    }

    func rotatedRight(_ amount: UInt32) -> UInt32 {
        (self &>> amount) | (self &<< ((32 &- amount) & 31))
    }
}
