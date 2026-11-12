/// AES-128, forward (encryption) cipher only.
///
/// The protocol uses AES-128 exclusively inside GCM, where every operation
/// runs the forward cipher on counter blocks. There is no inverse cipher to
/// implement.
struct AES128: Sendable {
    /// The whitening key plus one 16-byte round key per round.
    private let roundKeys: [[UInt8]]

    /// S-box derived from the field inverse and affine map instead of
    /// transcribed, so a typo cannot survive into the table.
    private static let sbox: [UInt8] = (0...255).map { affine(inverse($0)) }

    init(key: [UInt8]) {
        precondition(key.count == 16, "AES-128 keys are 16 bytes")

        // Key schedule: w[i] = w[i-4] XOR t, where t is w[i-1] rotated,
        // substituted and round-constant XORed at every fourth word.
        var w = key
        w.reserveCapacity(176)
        var rcon: UInt8 = 1
        for i in 4..<44 {
            var t = [UInt8](w[(i - 1) * 4 ..< i * 4])
            if i % 4 == 0 {
                t = [
                    Self.sbox[Int(t[1])], Self.sbox[Int(t[2])],
                    Self.sbox[Int(t[3])], Self.sbox[Int(t[0])],
                ]
                t[0] ^= rcon
                rcon = Self.xtime(rcon)
            }
            // The word four positions back; captured before the appends
            // shift `count` under us.
            let previousWordStart = w.count - 16
            for b in 0..<4 { w.append(w[previousWordStart + b] ^ t[b]) }
        }

        roundKeys = (0...10).map { [UInt8](w[$0 * 16 ..< $0 * 16 + 16]) }
    }

    /// Encrypts one 16-byte block in place.
    func encryptBlock(_ state: inout [UInt8]) {
        addRoundKey(&state, 0)
        for round in 1...10 {
            subBytes(&state)
            shiftRows(&state)
            if round < 10 { mixColumns(&state) }
            addRoundKey(&state, round)
        }
    }

    /// Encrypts one 16-byte block and returns the result.
    func encryptBlock(_ block: [UInt8]) -> [UInt8] {
        var state = block
        encryptBlock(&state)
        return state
    }

    // The state is stored column-major: index 4*column + row.

    private func addRoundKey(_ state: inout [UInt8], _ round: Int) {
        let rk = roundKeys[round]
        for i in 0..<16 { state[i] ^= rk[i] }
    }

    private func subBytes(_ state: inout [UInt8]) {
        for i in 0..<16 { state[i] = Self.sbox[Int(state[i])] }
    }

    /// Row r rotates left by r positions.
    private func shiftRows(_ state: inout [UInt8]) {
        let s = state
        for r in 1..<4 {
            for c in 0..<4 {
                state[4 * c + r] = s[4 * ((c + r) % 4) + r]
            }
        }
    }

    private func mixColumns(_ state: inout [UInt8]) {
        for c in 0..<4 {
            let x = [state[4 * c], state[4 * c + 1], state[4 * c + 2], state[4 * c + 3]]
            state[4 * c] = Self.xtime(x[0]) ^ Self.xtime(x[1]) ^ x[1] ^ x[2] ^ x[3]
            state[4 * c + 1] = x[0] ^ Self.xtime(x[1]) ^ Self.xtime(x[2]) ^ x[2] ^ x[3]
            state[4 * c + 2] = x[0] ^ x[1] ^ Self.xtime(x[2]) ^ Self.xtime(x[3]) ^ x[3]
            state[4 * c + 3] = Self.xtime(x[0]) ^ x[0] ^ x[1] ^ x[2] ^ Self.xtime(x[3])
        }
    }

    /// Multiply by x (the generator) in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
    private static func xtime(_ a: UInt8) -> UInt8 {
        let doubled = a << 1
        return a & 0x80 != 0 ? doubled ^ 0x1b : doubled
    }

    /// Inverse in GF(2^8); 0 maps to 0. Since a^255 = 1, a^254 = a^-1.
    private static func inverse(_ a: UInt8) -> UInt8 {
        var result: UInt8 = 1
        var base = a
        var exponent = 254
        while exponent > 0 {
            if exponent & 1 == 1 { result = gfMul(result, base) }
            base = gfMul(base, base)
            exponent >>= 1
        }
        return result
    }

    private static func gfMul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var p: UInt8 = 0
        var a = a
        var b = b
        for _ in 0..<8 {
            if b & 1 != 0 { p ^= a }
            let high = a & 0x80
            a <<= 1
            if high != 0 { a ^= 0x1b }
            b >>= 1
        }
        return p
    }

    /// The AES affine map: x XOR rot(x,1) XOR rot(x,2) XOR rot(x,3) XOR rot(x,4)
    /// XOR 0x63.
    private static func affine(_ x: UInt8) -> UInt8 {
        let r1 = x << 1 | x >> 7
        let r2 = x << 2 | x >> 6
        let r3 = x << 3 | x >> 5
        let r4 = x << 4 | x >> 4
        return x ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x63
    }
}
