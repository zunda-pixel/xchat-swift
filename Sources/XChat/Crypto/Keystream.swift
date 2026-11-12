extension UInt32 {
    /// Rotates left by `amount`, total over all amounts (masked shifts make
    /// the `amount == 0` case work out to the identity).
    func rotatedLeft(by amount: UInt32) -> UInt32 {
        (self &<< amount) | (self &>> ((32 &- amount) & 31))
    }
}

/// A keystream block generator with an internal block counter: the shape
/// the reference crypto stack gives its ChaCha and Salsa cores.
protocol StreamCipherCore: Sendable {
    /// Produces the next 64-byte keystream block, advancing the block
    /// counter.
    mutating func generateBlock() -> [UInt8]

    /// Jumps the block counter to `block`. ChaCha counters are 32-bit and
    /// truncate; Salsa counters are 64-bit.
    mutating func setBlockPosition(_ block: UInt64)
}

/// A stream cipher with the positioning semantics of the reference
/// stack's buffered wrapper, so seek and partial-block application behave
/// identically to the implementation the wire format is frozen against.
///
/// `xor` mirrors `apply_keystream`: leftover buffered keystream first, then
/// whole blocks straight from the core, then a fresh buffered block for the
/// tail. `seek` mirrors `try_seek`: the block counter jumps and a partial
/// block's remainder is buffered.
struct StreamCipher<Core: StreamCipherCore>: Sendable {
    private var core: Core
    /// Leftover keystream of the block being consumed.
    private var buffer: [UInt8] = []
    /// Bytes of `buffer` already consumed; 0 means no buffered keystream.
    private var pos = 0

    init(core: Core) {
        self.core = core
    }

    /// XORs keystream into `data[range]` (all of `data` when omitted), in
    /// place.
    mutating func xor(into data: inout [UInt8], range: Range<Int>? = nil) {
        let start = range?.lowerBound ?? 0
        let end = range?.upperBound ?? data.count
        var offset = start

        if pos != 0 {
            let available = buffer.count - pos
            let take = min(end - offset, available)
            if take < available {
                for i in 0..<take { data[offset + i] ^= buffer[pos + i] }
                pos += take
                return
            }
            for i in 0..<available { data[offset + i] ^= buffer[pos + i] }
            offset += available
        }

        while end - offset >= 64 {
            let block = core.generateBlock()
            for i in 0..<64 { data[offset + i] ^= block[i] }
            offset += 64
        }

        let leftover = end - offset
        if leftover > 0 { buffer = core.generateBlock() }
        for i in 0..<leftover { data[offset + i] ^= buffer[i] }
        pos = leftover
    }

    /// Repositions the keystream at an absolute byte offset: block counter
    /// `position / 64`, with any remainder buffered. `seek(to: 64)` starts
    /// at block 1, `seek(to: 128)` at block 2.
    mutating func seek(to position: UInt64) {
        let block = position / 64
        let byte = Int(position % 64)
        core.setBlockPosition(block)
        if byte != 0 { buffer = core.generateBlock() }
        pos = byte
    }
}
