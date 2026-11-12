/// The ChaCha20 core function: RFC 8439 state, 96-bit nonce, 32-bit block
/// counter. Ported word-for-word from the software backend the wire format
/// is frozen against, including the wrapping counter increment.
struct ChaCha20Core: StreamCipherCore, Sendable {
    private var state: [UInt32]

    init(key: [UInt8], nonce: [UInt8]) {
        precondition(key.count == 32, "ChaCha20 keys are 32 bytes")
        precondition(nonce.count == 12, "ChaCha20 nonces are 12 bytes")
        var words = [UInt32](repeating: 0, count: 16)
        for i in 0..<4 { words[i] = Self.constants[i] }
        for i in 0..<8 { words[4 + i] = key.le32(at: i * 4) }
        // words[12] is the block counter and starts at zero.
        for i in 0..<3 { words[13 + i] = nonce.le32(at: i * 4) }
        state = words
    }

    mutating func generateBlock() -> [UInt8] {
        var x = state
        Self.rounds(&x)

        var block = [UInt8](repeating: 0, count: 64)
        for i in 0..<16 {
            block.replaceSubrange(i * 4..<i * 4 + 4, with: (x[i] &+ state[i]).leBytes)
        }
        state[12] &+= 1
        return block
    }

    mutating func setBlockPosition(_ block: UInt64) {
        state[12] = UInt32(truncatingIfNeeded: block)
    }

    /// "expand 32-byte k".
    fileprivate static let constants: [UInt32] = [
        0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
    ]

    /// The ten double rounds, without the feed-forward addition HChaCha20
    /// shares.
    fileprivate static func rounds(_ x: inout [UInt32]) {
        for _ in 0..<10 { doubleRound(&x) }
    }

    /// One pair of column and diagonal rounds.
    private static func doubleRound(_ x: inout [UInt32]) {
        quarterRound(0, 4, 8, 12, &x)
        quarterRound(1, 5, 9, 13, &x)
        quarterRound(2, 6, 10, 14, &x)
        quarterRound(3, 7, 11, 15, &x)

        quarterRound(0, 5, 10, 15, &x)
        quarterRound(1, 6, 11, 12, &x)
        quarterRound(2, 7, 8, 13, &x)
        quarterRound(3, 4, 9, 14, &x)
    }

    private static func quarterRound(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: inout [UInt32]) {
        x[a] = x[a] &+ x[b]
        x[d] ^= x[a]
        x[d] = x[d].rotatedLeft(by: 16)

        x[c] = x[c] &+ x[d]
        x[b] ^= x[c]
        x[b] = x[b].rotatedLeft(by: 12)

        x[a] = x[a] &+ x[b]
        x[d] ^= x[a]
        x[d] = x[d].rotatedLeft(by: 8)

        x[c] = x[c] &+ x[d]
        x[b] ^= x[c]
        x[b] = x[b].rotatedLeft(by: 7)
    }
}

/// The ChaCha20 stream cipher (RFC 8439, 96-bit nonce).
typealias ChaCha20 = StreamCipher<ChaCha20Core>

extension StreamCipher where Core == ChaCha20Core {
    /// ChaCha20 with a 32-byte key and 12-byte nonce; the block counter
    /// starts at 0. Use `seek(to:)` for the counter-1 start other RFC 8439
    /// constructions use.
    init(key: [UInt8], nonce: [UInt8]) {
        self.init(core: ChaCha20Core(key: key, nonce: nonce))
    }
}

/// The HChaCha20 key-derivation function: the ChaCha round function run
/// without the feed-forward addition, emitting words 0-3 and 12-15 as the
/// subkey. Used by the media stream to build its header-derived key.
func hchacha20(key: [UInt8], input: [UInt8]) -> [UInt8] {
    precondition(key.count == 32, "HChaCha20 keys are 32 bytes")
    precondition(input.count == 16, "HChaCha20 inputs are 16 bytes")

    var x = [UInt32](repeating: 0, count: 16)
    for i in 0..<4 { x[i] = ChaCha20Core.constants[i] }
    for i in 0..<8 { x[4 + i] = key.le32(at: i * 4) }
    for i in 0..<4 { x[12 + i] = input.le32(at: i * 4) }

    ChaCha20Core.rounds(&x)

    var output = [UInt8]()
    output.reserveCapacity(32)
    for i in 0..<4 { output += x[i].leBytes }
    for i in 12..<16 { output += x[i].leBytes }
    return output
}
