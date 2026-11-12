/// The Salsa20 core function: "expand 32-byte k" state, 64-bit nonce words,
/// 64-bit block counter in words 8-9. Ported word-for-word from the
/// implementation the wire format is frozen against, including the
/// get-increment-set counter update with its 64-bit carry.
struct Salsa20Core: StreamCipherCore, Sendable {
    private var state: [UInt32]

    init(key: [UInt8], nonce: [UInt8]) {
        precondition(key.count == 32, "Salsa20 keys are 32 bytes")
        precondition(nonce.count == 8, "Salsa20 nonces are 8 bytes")
        var words = [UInt32](repeating: 0, count: 16)
        words[0] = Self.constants[0]
        for i in 0..<4 { words[1 + i] = key.le32(at: i * 4) }
        words[5] = Self.constants[1]
        for i in 0..<2 { words[6 + i] = nonce.le32(at: i * 4) }
        // words[8] and words[9] are the 64-bit block counter, starting at 0.
        words[10] = Self.constants[2]
        for i in 0..<4 { words[11 + i] = key.le32(at: 16 + i * 4) }
        words[15] = Self.constants[3]
        state = words
    }

    mutating func generateBlock() -> [UInt8] {
        var x = state
        Self.rounds(&x)

        var block = [UInt8](repeating: 0, count: 64)
        for i in 0..<16 {
            block.replaceSubrange(i * 4..<i * 4 + 4, with: (x[i] &+ state[i]).leBytes)
        }
        setBlockPosition(blockPosition() + 1)
        return block
    }

    mutating func setBlockPosition(_ block: UInt64) {
        state[8] = UInt32(truncatingIfNeeded: block)
        state[9] = UInt32(truncatingIfNeeded: block >> 32)
    }

    private func blockPosition() -> UInt64 {
        UInt64(state[8]) | UInt64(state[9]) << 32
    }

    /// "expand 32-byte k".
    fileprivate static let constants: [UInt32] = [
        0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
    ]

    /// The ten double rounds, without the feed-forward addition HSalsa20
    /// shares.
    fileprivate static func rounds(_ x: inout [UInt32]) {
        for _ in 0..<10 { doubleRound(&x) }
    }

    /// One pair of column and diagonal rounds.
    private static func doubleRound(_ x: inout [UInt32]) {
        quarterRound(0, 4, 8, 12, &x)
        quarterRound(5, 9, 13, 1, &x)
        quarterRound(10, 14, 2, 6, &x)
        quarterRound(15, 3, 7, 11, &x)

        quarterRound(0, 1, 2, 3, &x)
        quarterRound(5, 6, 7, 4, &x)
        quarterRound(10, 11, 8, 9, &x)
        quarterRound(15, 12, 13, 14, &x)
    }

    private static func quarterRound(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: inout [UInt32]) {
        x[b] ^= (x[a] &+ x[d]).rotatedLeft(by: 7)
        x[c] ^= (x[b] &+ x[a]).rotatedLeft(by: 9)
        x[d] ^= (x[c] &+ x[b]).rotatedLeft(by: 13)
        x[a] ^= (x[d] &+ x[c]).rotatedLeft(by: 18)
    }
}

/// The Salsa20 stream cipher (8-byte nonce).
typealias Salsa20 = StreamCipher<Salsa20Core>

extension StreamCipher where Core == Salsa20Core {
    /// Salsa20 with a 32-byte key and 8-byte nonce.
    init(key: [UInt8], nonce: [UInt8]) {
        self.init(core: Salsa20Core(key: key, nonce: nonce))
    }

    /// XSalsa20 with a 32-byte key and 24-byte nonce: HSalsa20 hashes the
    /// key and the first 16 nonce bytes into a subkey, under which Salsa20
    /// runs with the last 8.
    static func xsalsa(key: [UInt8], nonce: [UInt8]) -> StreamCipher<Salsa20Core> {
        StreamCipher(core: Salsa20Core(
            key: hsalsa20(key: key, input: Array(nonce[0..<16])),
            nonce: Array(nonce[16..<24])))
    }
}

/// The HSalsa20 key-derivation function: the Salsa round function run
/// without the feed-forward addition, emitting words 0, 5, 10, 15, 6, 7, 8
/// and 9 as the subkey.
func hsalsa20(key: [UInt8], input: [UInt8]) -> [UInt8] {
    precondition(key.count == 32, "HSalsa20 keys are 32 bytes")
    precondition(input.count == 16, "HSalsa20 inputs are 16 bytes")

    var x = [UInt32](repeating: 0, count: 16)
    x[0] = Salsa20Core.constants[0]
    for i in 0..<4 { x[1 + i] = key.le32(at: i * 4) }
    x[5] = Salsa20Core.constants[1]
    for i in 0..<4 { x[6 + i] = input.le32(at: i * 4) }
    x[10] = Salsa20Core.constants[2]
    for i in 0..<4 { x[11 + i] = key.le32(at: 16 + i * 4) }
    x[15] = Salsa20Core.constants[3]

    Salsa20Core.rounds(&x)

    let outputIndices = [0, 5, 10, 15, 6, 7, 8, 9]
    var output = [UInt8]()
    output.reserveCapacity(32)
    for i in outputIndices { output += x[i].leBytes }
    return output
}
