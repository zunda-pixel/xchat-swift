import Algorithms

/// Poly1305 in the 32-bit "donna" formulation: every value is five 26-bit
/// limbs, and block reads use overlapping byte windows (bytes 0-4, 3-7, 6-10,
/// 9-13, 12-16). The reference crypto stack the wire format is frozen
/// against runs exactly this arithmetic, so the port stays limb-for-limb
/// faithful, including its wrapping carry behavior.
///
/// Two input conventions exist, both needed by the protocol:
/// - `updatePadded` feeds full blocks and zero-padded partial blocks, with
///   the 2^128 bit added by the hash itself. AEAD constructions use this.
/// - `computeUnpadded` expects the final partial block to carry its own 0x01
///   padding byte, which supplies the 2^(8·len) term. Plain one-shot
///   Poly1305 (as in RFC 8439) uses this.
struct Poly1305: Sendable {
    /// Clamped multiplier, five 26-bit limbs.
    private var r: [UInt32]
    /// Accumulator, five 26-bit limbs.
    private var h: [UInt32]
    /// The `s` half of the key, added to the final accumulator.
    private var pad: [UInt32]

    init(key: [UInt8]) {
        precondition(key.count == 32, "Poly1305 keys are 32 bytes")
        // The overlapping windows clamp r to 0xffffffc0ffffffc0ffffffc0fffffff.
        r = [
            key.le32(at: 0) & 0x3ffffff,
            (key.le32(at: 3) >> 2) & 0x3ffff03,
            (key.le32(at: 6) >> 4) & 0x3ffc0ff,
            (key.le32(at: 9) >> 6) & 0x3f03fff,
            (key.le32(at: 12) >> 8) & 0x00fffff,
        ]
        h = [0, 0, 0, 0, 0]
        pad = [key.le32(at: 16), key.le32(at: 20), key.le32(at: 24), key.le32(at: 28)]
    }

    /// Absorbs one 16-byte block. A `partial` block carries its own 2^128
    /// coefficient in the 0x01 padding byte, so the high bit of limb 4 is
    /// not added on top of it.
    mutating func processBlock(_ block: ArraySlice<UInt8>, partial: Bool = false) {
        precondition(block.count == 16, "Poly1305 blocks are 16 bytes")
        let hibit: UInt32 = partial ? 0 : 1 << 24

        let r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4]
        let s1 = r1 &* 5
        let s2 = r2 &* 5
        let s3 = r3 &* 5
        let s4 = r4 &* 5

        var h0 = h[0]
        var h1 = h[1]
        var h2 = h[2]
        var h3 = h[3]
        var h4 = h[4]

        // h += m
        h0 += block.le32(at: 0) & 0x3ffffff
        h1 += (block.le32(at: 3) >> 2) & 0x3ffffff
        h2 += (block.le32(at: 6) >> 4) & 0x3ffffff
        h3 += (block.le32(at: 9) >> 6) & 0x3ffffff
        h4 += block.le32(at: 12) >> 8 | hibit

        // h *= r
        let d0 =
            UInt64(h0) * UInt64(r0) + UInt64(h1) * UInt64(s4)
            + UInt64(h2) * UInt64(s3) + UInt64(h3) * UInt64(s2)
            + UInt64(h4) * UInt64(s1)

        var d1 =
            UInt64(h0) * UInt64(r1) + UInt64(h1) * UInt64(r0)
            + UInt64(h2) * UInt64(s4) + UInt64(h3) * UInt64(s3)
            + UInt64(h4) * UInt64(s2)

        var d2 =
            UInt64(h0) * UInt64(r2) + UInt64(h1) * UInt64(r1)
            + UInt64(h2) * UInt64(r0) + UInt64(h3) * UInt64(s4)
            + UInt64(h4) * UInt64(s3)

        var d3 =
            UInt64(h0) * UInt64(r3) + UInt64(h1) * UInt64(r2)
            + UInt64(h2) * UInt64(r1) + UInt64(h3) * UInt64(r0)
            + UInt64(h4) * UInt64(s4)

        var d4 =
            UInt64(h0) * UInt64(r4) + UInt64(h1) * UInt64(r3)
            + UInt64(h2) * UInt64(r2) + UInt64(h3) * UInt64(r1)
            + UInt64(h4) * UInt64(r0)

        // (partial) h %= p
        var c = UInt32(truncatingIfNeeded: d0 >> 26)
        h0 = UInt32(truncatingIfNeeded: d0) & 0x3ffffff
        d1 += UInt64(c)

        c = UInt32(truncatingIfNeeded: d1 >> 26)
        h1 = UInt32(truncatingIfNeeded: d1) & 0x3ffffff
        d2 += UInt64(c)

        c = UInt32(truncatingIfNeeded: d2 >> 26)
        h2 = UInt32(truncatingIfNeeded: d2) & 0x3ffffff
        d3 += UInt64(c)

        c = UInt32(truncatingIfNeeded: d3 >> 26)
        h3 = UInt32(truncatingIfNeeded: d3) & 0x3ffffff
        d4 += UInt64(c)

        c = UInt32(truncatingIfNeeded: d4 >> 26)
        h4 = UInt32(truncatingIfNeeded: d4) & 0x3ffffff
        h0 += c * 5

        c = h0 >> 26
        h0 &= 0x3ffffff
        h1 += c

        h = [h0, h1, h2, h3, h4]
    }

    /// Absorbs data under the AEAD convention: full blocks and a zero-padded
    /// partial block, all with the hash's own 2^128 bit.
    mutating func updatePadded(_ data: [UInt8]) {
        let fullLength = data.count / 16 * 16
        for chunk in data[0..<fullLength].chunks(ofCount: 16) {
            processBlock(chunk[...])
        }
        let tailCount = data.count - fullLength
        if tailCount > 0 {
            var block = [UInt8](repeating: 0, count: 16)
            block.replaceSubrange(0..<tailCount, with: data[fullLength...])
            processBlock(block[...])
        }
    }

    /// Absorbs data under the one-shot convention — the final partial block
    /// gets a 0x01 byte at its length — then produces the tag. Treats the
    /// state as consumed, as the reference does.
    mutating func computeUnpadded(_ data: [UInt8]) -> [UInt8] {
        let fullLength = data.count / 16 * 16
        for chunk in data[0..<fullLength].chunks(ofCount: 16) {
            processBlock(chunk[...])
        }
        let tailCount = data.count - fullLength
        if tailCount > 0 {
            var block = [UInt8](repeating: 0, count: 16)
            block.replaceSubrange(0..<tailCount, with: data[fullLength...])
            block[tailCount] = 1
            processBlock(block[...], partial: true)
        }
        return finalize()
    }

    /// Reduces the accumulator fully and adds the `s` half of the key.
    mutating func finalize() -> [UInt8] {
        // Fully carry h.
        var h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4]
        var c: UInt32

        c = h1 >> 26
        h1 &= 0x3ffffff
        h2 += c

        c = h2 >> 26
        h2 &= 0x3ffffff
        h3 += c

        c = h3 >> 26
        h3 &= 0x3ffffff
        h4 += c

        c = h4 >> 26
        h4 &= 0x3ffffff
        h0 += c * 5

        c = h0 >> 26
        h0 &= 0x3ffffff
        h1 += c

        // Compute h + -p.
        var g0 = h0 &+ 5
        c = g0 >> 26
        g0 &= 0x3ffffff

        var g1 = h1 &+ c
        c = g1 >> 26
        g1 &= 0x3ffffff

        var g2 = h2 &+ c
        c = g2 >> 26
        g2 &= 0x3ffffff

        var g3 = h3 &+ c
        c = g3 >> 26
        g3 &= 0x3ffffff

        var g4 = h4 &+ c &- (1 << 26)

        // Select h if h < p, or h + -p if h >= p.
        var mask = (g4 >> 31) &- 1
        g0 &= mask
        g1 &= mask
        g2 &= mask
        g3 &= mask
        g4 &= mask
        mask = ~mask
        h0 = h0 & mask | g0
        h1 = h1 & mask | g1
        h2 = h2 & mask | g2
        h3 = h3 & mask | g3
        h4 = h4 & mask | g4

        // h = h % (2^128).
        h0 |= h1 << 26
        h1 = h1 >> 6 | h2 << 20
        h2 = h2 >> 12 | h3 << 14
        h3 = h3 >> 18 | h4 << 8

        // h = mac = (h + pad) % (2^128).
        var f = UInt64(h0) + UInt64(pad[0])
        h0 = UInt32(truncatingIfNeeded: f)

        f = UInt64(h1) + UInt64(pad[1]) + (f >> 32)
        h1 = UInt32(truncatingIfNeeded: f)

        f = UInt64(h2) + UInt64(pad[2]) + (f >> 32)
        h2 = UInt32(truncatingIfNeeded: f)

        f = UInt64(h3) + UInt64(pad[3]) + (f >> 32)
        h3 = UInt32(truncatingIfNeeded: f)

        return h0.leBytes + h1.leBytes + h2.leBytes + h3.leBytes
    }
}
