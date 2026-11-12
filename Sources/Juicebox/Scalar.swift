/// The scalar field Z/ℓ, where ℓ = 2^252 + 27742317777372353535851937790883648493,
/// in radix 2^52 with five `UInt64` limbs. The 52-bit width leaves room to
/// reduce a 512-bit product with Montgomery multiplication.
struct Scalar52: Sendable, Equatable {
    var limbs: [UInt64]

    init(_ limbs: [UInt64]) {
        precondition(limbs.count == 5, "scalars have five limbs")
        self.limbs = limbs
    }

    static let zero = Scalar52([0, 0, 0, 0, 0])
    static let one = Scalar52([1, 0, 0, 0, 0])

    /// ℓ, the group order.
    static let order = Scalar52([
        0x0002_631a_5cf5_d3ed, 0x000d_ea2f_79cd_6581, 0x0000_0000_0014_def9,
        0x0000_0000_0000_0000, 0x0000_1000_0000_0000,
    ])

    /// ℓ - 2, the exponent that inverts a nonzero scalar.
    static let orderMinusTwo = Scalar52([
        0x0002_631a_5cf5_d3eb, 0x000d_ea2f_79cd_6581, 0x0000_0000_0014_def9,
        0x0000_0000_0000_0000, 0x0000_1000_0000_0000,
    ])

    /// `ℓ * LFACTOR = -1 (mod 2^52)`.
    static let lfactor: UInt64 = 0x51da_3125_47e1b

    /// `R = 2^260 (mod ℓ)`.
    static let r = Scalar52([
        0x000f_48bd_6721_e6ed, 0x0003_bab5_ac67_e45a, 0x000f_ffff_eb35_e51b,
        0x000f_ffff_ffff_ffff, 0x0000_0fff_ffff_ffff,
    ])

    /// `RR = R^2 (mod ℓ)`.
    static let rr = Scalar52([
        0x0009_d265_e952_d13b, 0x000d_63c7_15be_a69f, 0x0005_be65_cb68_7604,
        0x0003_dcee_c73d_217f, 0x0000_0941_1b7c_309a,
    ])

    // MARK: Encoding

    /// Unpacks 32 little-endian bytes without reducing; callers that need a
    /// canonical scalar reduce first.
    static func fromBytes(_ bytes: [UInt8]) -> Scalar52 {
        precondition(bytes.count == 32)
        var words = [UInt64](repeating: 0, count: 4)
        for i in 0..<4 {
            for j in 0..<8 {
                words[i] |= UInt64(bytes[i * 8 + j]) << (8 * UInt64(j))
            }
        }
        let mask: UInt64 = (1 << 52) - 1
        let topMask: UInt64 = (1 << 48) - 1
        return Scalar52([
            words[0] & mask,
            ((words[0] >> 52) | (words[1] << 12)) & mask,
            ((words[1] >> 40) | (words[2] << 24)) & mask,
            ((words[2] >> 28) | (words[3] << 36)) & mask,
            (words[3] >> 16) & topMask,
        ])
    }

    /// Reduces a 512-bit little-endian value modulo ℓ.
    static func fromBytesWide(_ bytes: [UInt8]) -> Scalar52 {
        precondition(bytes.count == 64)
        var words = [UInt64](repeating: 0, count: 8)
        for i in 0..<8 {
            for j in 0..<8 {
                words[i] |= UInt64(bytes[i * 8 + j]) << (8 * UInt64(j))
            }
        }
        let mask: UInt64 = (1 << 52) - 1
        let lo = Scalar52([
            words[0] & mask,
            ((words[0] >> 52) | (words[1] << 12)) & mask,
            ((words[1] >> 40) | (words[2] << 24)) & mask,
            ((words[2] >> 28) | (words[3] << 36)) & mask,
            ((words[3] >> 16) | (words[4] << 48)) & mask,
        ])
        let hi = Scalar52([
            (words[4] >> 4) & mask,
            ((words[4] >> 56) | (words[5] << 8)) & mask,
            ((words[5] >> 44) | (words[6] << 20)) & mask,
            ((words[6] >> 32) | (words[7] << 32)) & mask,
            words[7] >> 20,
        ])
        let loR = montgomeryMul(lo, r)
        let hiR = montgomeryMul(hi, rr)
        return add(hiR, loR)
    }

    /// Packs the limbs into 32 little-endian bytes.
    func asBytes() -> [UInt8] {
        let a = limbs
        var s = [UInt8](repeating: 0, count: 32)
        s[0] = UInt8(truncatingIfNeeded: a[0])
        s[1] = UInt8(truncatingIfNeeded: a[0] >> 8)
        s[2] = UInt8(truncatingIfNeeded: a[0] >> 16)
        s[3] = UInt8(truncatingIfNeeded: a[0] >> 24)
        s[4] = UInt8(truncatingIfNeeded: a[0] >> 32)
        s[5] = UInt8(truncatingIfNeeded: a[0] >> 40)
        s[6] = UInt8(truncatingIfNeeded: (a[0] >> 48) | (a[1] << 4))
        s[7] = UInt8(truncatingIfNeeded: a[1] >> 4)
        s[8] = UInt8(truncatingIfNeeded: a[1] >> 12)
        s[9] = UInt8(truncatingIfNeeded: a[1] >> 20)
        s[10] = UInt8(truncatingIfNeeded: a[1] >> 28)
        s[11] = UInt8(truncatingIfNeeded: a[1] >> 36)
        s[12] = UInt8(truncatingIfNeeded: a[1] >> 44)
        s[13] = UInt8(truncatingIfNeeded: a[2])
        s[14] = UInt8(truncatingIfNeeded: a[2] >> 8)
        s[15] = UInt8(truncatingIfNeeded: a[2] >> 16)
        s[16] = UInt8(truncatingIfNeeded: a[2] >> 24)
        s[17] = UInt8(truncatingIfNeeded: a[2] >> 32)
        s[18] = UInt8(truncatingIfNeeded: a[2] >> 40)
        s[19] = UInt8(truncatingIfNeeded: (a[2] >> 48) | (a[3] << 4))
        s[20] = UInt8(truncatingIfNeeded: a[3] >> 4)
        s[21] = UInt8(truncatingIfNeeded: a[3] >> 12)
        s[22] = UInt8(truncatingIfNeeded: a[3] >> 20)
        s[23] = UInt8(truncatingIfNeeded: a[3] >> 28)
        s[24] = UInt8(truncatingIfNeeded: a[3] >> 36)
        s[25] = UInt8(truncatingIfNeeded: a[3] >> 44)
        s[26] = UInt8(truncatingIfNeeded: a[4])
        s[27] = UInt8(truncatingIfNeeded: a[4] >> 8)
        s[28] = UInt8(truncatingIfNeeded: a[4] >> 16)
        s[29] = UInt8(truncatingIfNeeded: a[4] >> 24)
        s[30] = UInt8(truncatingIfNeeded: a[4] >> 32)
        s[31] = UInt8(truncatingIfNeeded: a[4] >> 40)
        return s
    }

    // MARK: Arithmetic

    /// `a + b (mod ℓ)`.
    static func add(_ a: Scalar52, _ b: Scalar52) -> Scalar52 {
        let mask: UInt64 = (1 << 52) - 1
        var sum = Scalar52.zero
        var carry: UInt64 = 0
        for i in 0..<5 {
            carry = a.limbs[i] &+ b.limbs[i] &+ (carry >> 52)
            sum.limbs[i] = carry & mask
        }
        return sub(sum, order)
    }

    /// `a - b (mod ℓ)`.
    static func sub(_ a: Scalar52, _ b: Scalar52) -> Scalar52 {
        let mask: UInt64 = (1 << 52) - 1
        var difference = Scalar52.zero
        var borrow: UInt64 = 0
        for i in 0..<5 {
            borrow = a.limbs[i] &- (b.limbs[i] &+ (borrow >> 63))
            difference.limbs[i] = borrow & mask
        }
        // Add ℓ when the subtraction underflowed.
        let underflowMask = ((borrow >> 63) ^ 1) &- 1
        var carry: UInt64 = 0
        for i in 0..<5 {
            carry = (carry >> 52) &+ difference.limbs[i] &+ (order.limbs[i] & underflowMask)
            difference.limbs[i] = carry & mask
        }
        return difference
    }

    static prefix func - (value: Scalar52) -> Scalar52 {
        sub(.zero, value)
    }

    static func + (lhs: Scalar52, rhs: Scalar52) -> Scalar52 { add(lhs, rhs) }
    static func - (lhs: Scalar52, rhs: Scalar52) -> Scalar52 { sub(lhs, rhs) }
    static func * (lhs: Scalar52, rhs: Scalar52) -> Scalar52 { mul(lhs, rhs) }

    private static func m(_ x: UInt64, _ y: UInt64) -> UInt128 {
        UInt128(x) &* UInt128(y)
    }

    /// The 9-limb schoolbook product `a * b`, before reduction.
    private static func mulInternal(_ a: Scalar52, _ b: Scalar52) -> [UInt128] {
        let x = a.limbs
        let y = b.limbs
        return [
            m(x[0], y[0]),
            m(x[0], y[1]) + m(x[1], y[0]),
            m(x[0], y[2]) + m(x[1], y[1]) + m(x[2], y[0]),
            m(x[0], y[3]) + m(x[1], y[2]) + m(x[2], y[1]) + m(x[3], y[0]),
            m(x[0], y[4]) + m(x[1], y[3]) + m(x[2], y[2]) + m(x[3], y[1]) + m(x[4], y[0]),
            m(x[1], y[4]) + m(x[2], y[3]) + m(x[3], y[2]) + m(x[4], y[1]),
            m(x[2], y[4]) + m(x[3], y[3]) + m(x[4], y[2]),
            m(x[3], y[4]) + m(x[4], y[3]),
            m(x[4], y[4]),
        ]
    }

    /// The 9-limb square `a^2`, before reduction.
    private static func squareInternal(_ a: Scalar52) -> [UInt128] {
        let x = a.limbs
        let aa = [x[0] &* 2, x[1] &* 2, x[2] &* 2, x[3] &* 2]
        return [
            m(x[0], x[0]),
            m(aa[0], x[1]),
            m(aa[0], x[2]) + m(x[1], x[1]),
            m(aa[0], x[3]) + m(aa[1], x[2]),
            m(aa[0], x[4]) + m(aa[1], x[3]) + m(x[2], x[2]),
            m(aa[1], x[4]) + m(aa[2], x[3]),
            m(aa[2], x[4]) + m(x[3], x[3]),
            m(aa[3], x[4]),
            m(x[4], x[4]),
        ]
    }

    /// Divides by the Montgomery modulus `R = 2^260 (mod ℓ)`.
    static func montgomeryReduce(_ limbs: [UInt128]) -> Scalar52 {
        let mask: UInt64 = (1 << 52) - 1
        let l = order.limbs

        func part1(_ sum: UInt128) -> (UInt128, UInt64) {
            let p = (UInt64(truncatingIfNeeded: sum) &* lfactor) & mask
            return ((sum + m(p, l[0])) >> 52, p)
        }
        func part2(_ sum: UInt128) -> (UInt128, UInt64) {
            (sum >> 52, UInt64(truncatingIfNeeded: sum) & mask)
        }

        let (carry0, n0) = part1(limbs[0])
        let (carry1, n1) = part1(carry0 + limbs[1] + m(n0, l[1]))
        let (carry2, n2) = part1(carry1 + limbs[2] + m(n0, l[2]) + m(n1, l[1]))
        let (carry3, n3) = part1(carry2 + limbs[3] + m(n1, l[2]) + m(n2, l[1]))
        let (carry4, n4) = part1(
            carry3 + limbs[4] + m(n0, l[4]) + m(n2, l[2]) + m(n3, l[1]))

        let (carry5, r0) = part2(
            carry4 + limbs[5] + m(n1, l[4]) + m(n3, l[2]) + m(n4, l[1]))
        let (carry6, r1) = part2(carry5 + limbs[6] + m(n2, l[4]) + m(n4, l[2]))
        let (carry7, r2) = part2(carry6 + limbs[7] + m(n3, l[4]))
        let (r4, r3) = part2(carry7 + limbs[8] + m(n4, l[4]))

        return sub(Scalar52([r0, r1, r2, r3, UInt64(truncatingIfNeeded: r4)]), order)
    }

    /// `a * b (mod ℓ)`.
    static func mul(_ a: Scalar52, _ b: Scalar52) -> Scalar52 {
        let ab = montgomeryReduce(mulInternal(a, b))
        return montgomeryReduce(mulInternal(ab, rr))
    }

    /// `a^2 (mod ℓ)`.
    func square() -> Scalar52 {
        let aa = Scalar52.montgomeryReduce(Scalar52.squareInternal(self))
        return Scalar52.montgomeryReduce(Scalar52.mulInternal(aa, Scalar52.rr))
    }

    /// `(a * b) / R (mod ℓ)`.
    static func montgomeryMul(_ a: Scalar52, _ b: Scalar52) -> Scalar52 {
        montgomeryReduce(mulInternal(a, b))
    }

    /// `a * R (mod ℓ)`, entering Montgomery form.
    func asMontgomery() -> Scalar52 { Scalar52.montgomeryMul(self, Scalar52.rr) }

    /// `a / R (mod ℓ)`, leaving Montgomery form.
    func fromMontgomery() -> Scalar52 {
        var limbs = [UInt128](repeating: 0, count: 9)
        for i in 0..<5 {
            limbs[i] = UInt128(self.limbs[i])
        }
        return Scalar52.montgomeryReduce(limbs)
    }

    /// `a^(ℓ-2) (mod ℓ)`, the multiplicative inverse of a nonzero scalar.
    ///
    /// The exponent is a public constant, so branching on its bits is fine;
    /// the base is secret and stays in the fixed multiply/square sequence.
    func invert() -> Scalar52 {
        var result = Scalar52.one
        for bit in stride(from: 255, through: 0, by: -1) {
            result = result.square()
            let set = (Scalar52.orderMinusTwo.limbs[bit / 52] >> UInt64(bit % 52)) & 1 == 1
            if set {
                result = result * self
            }
        }
        return result
    }

    var isZero: Bool {
        limbs.allSatisfy { $0 == 0 }
    }
}
