/// BLAKE2b-512 (RFC 7693), and the variable-length output mode Argon2's
/// `H'` uses. Argon2 builds its compression and initial hash on BLAKE2b.
struct Blake2b {
    private static let iv: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B,
        0xA54F_F53A_5F1D_36F1, 0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F,
        0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]

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

    private var h: [UInt64]
    private var buffer: [UInt8] = []
    private let outputLength: Int

    init(outputLength: Int = 64) {
        precondition(outputLength >= 1 && outputLength <= 64, "BLAKE2b output is 1...64 bytes")
        self.outputLength = outputLength
        var state = Self.iv
        state[0] ^= 0x0101_0000 ^ UInt64(outputLength)
        h = state
    }

    mutating func update(_ data: [UInt8]) {
        buffer.append(contentsOf: data)
    }

    mutating func finalize() -> [UInt8] {
        let byteCount = UInt64(buffer.count)
        var fullBlocks = buffer.count / 128
        if buffer.count % 128 == 0, buffer.count > 0 {
            fullBlocks -= 1
        }
        var offset = 0
        for _ in 0..<fullBlocks {
            compress(
                Array(buffer[offset..<offset + 128]), last: false,
                counted: UInt64(offset + 128))
            offset += 128
        }
        var last = Array(buffer[offset...])
        if last.count < 128 {
            last.append(contentsOf: [UInt8](repeating: 0, count: 128 - last.count))
        }
        compress(last, last: true, counted: byteCount)

        var out: [UInt8] = []
        out.reserveCapacity(64)
        for word in h { out.append(contentsOf: word.leBytes) }
        return Array(out.prefix(outputLength))
    }

    static func hash(_ data: [UInt8], outputLength: Int = 64) -> [UInt8] {
        var hasher = Blake2b(outputLength: outputLength)
        hasher.update(data)
        return hasher.finalize()
    }

    private mutating func compress(_ block: [UInt8], last: Bool, counted: UInt64) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt64(block[i * 8])
                | UInt64(block[i * 8 + 1]) << 8
                | UInt64(block[i * 8 + 2]) << 16
                | UInt64(block[i * 8 + 3]) << 24
                | UInt64(block[i * 8 + 4]) << 32
                | UInt64(block[i * 8 + 5]) << 40
                | UInt64(block[i * 8 + 6]) << 48
                | UInt64(block[i * 8 + 7]) << 56
        }
        var v = h + Self.iv
        v[12] ^= counted
        if last { v[14] = ~v[14] }

        for round in 0..<12 {
            let s = Self.sigma[round % 10]
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
        _ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64
    ) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotatedRight(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotatedRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(63)
    }
}

/// Argon2's variable-length hash `H'`: for outputs up to 64 bytes it is a
/// BLAKE2b of the length and input; longer outputs chain 32-byte halves of
/// successive BLAKE2b-512 digests and hash the tail with the remaining size.
func blake2bLong(_ input: [UInt8], length: Int) -> [UInt8] {
    precondition(length >= 1, "H' output is at least one byte")
    // The length prefix is little-endian.
    let lengthBytes: [UInt8] = [
        UInt8(truncatingIfNeeded: length),
        UInt8(truncatingIfNeeded: length >> 8),
        UInt8(truncatingIfNeeded: length >> 16),
        UInt8(truncatingIfNeeded: length >> 24),
    ]
    if length <= 64 {
        return Blake2b.hash(lengthBytes + input, outputLength: length)
    }
    var out = [UInt8](repeating: 0, count: length)
    var last = Blake2b.hash(lengthBytes + input, outputLength: 64)
    out.replaceSubrange(0..<32, with: last[0..<32])

    var counter = 0
    var offset = 32
    while true {
        counter += 32
        if length - counter <= 64 { break }
        last = Blake2b.hash(last, outputLength: 64)
        out.replaceSubrange(offset..<(offset + 32), with: last[0..<32])
        offset += 32
    }
    out.replaceSubrange(
        counter..<length, with: Blake2b.hash(last, outputLength: length - counter))
    return out
}

func be32(_ value: UInt32) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
    ]
}

extension UInt64 {
    var leBytes: [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: self >> (8 * UInt64($0))) }
    }

    func rotatedRight(_ amount: UInt64) -> UInt64 {
        (self &>> amount) | (self &<< ((64 &- amount) & 63))
    }
}
