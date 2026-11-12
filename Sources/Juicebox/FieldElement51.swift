/// A constant-time boolean, carried as an all-ones or all-zero mask so
/// selections and conditional moves never branch on secret data.
struct Choice: Sendable {
    let mask: UInt64

    init(_ value: Bool) {
        mask = 0 &- (value ? 1 : 0)
    }

    init(mask: UInt64) {
        self.mask = 0 &- (mask & 1)
    }

    var boolValue: Bool { mask & 1 == 1 }

    static let one = Choice(mask: 0 &- 1)
    static let zero = Choice(mask: 0)

    func or(_ other: Choice) -> Choice {
        Choice(mask: mask | other.mask)
    }

    func and(_ other: Choice) -> Choice {
        Choice(mask: mask & other.mask)
    }

    static prefix func ! (value: Choice) -> Choice {
        Choice(mask: ~value.mask)
    }
}

/// The field Z/(2^255 - 19), in radix 2^51 with five `UInt64` limbs, ported
/// from the reference implementation the Ristretto group is frozen against.
/// Limbs may grow to 2^54 between reductions.
struct FieldElement51: Sendable {
    var limbs: [UInt64]

    init(limbs: [UInt64]) {
        precondition(limbs.count == 5, "field elements have five limbs")
        self.limbs = limbs
    }

    static let zero = FieldElement51(limbs: [0, 0, 0, 0, 0])
    static let one = FieldElement51(limbs: [1, 0, 0, 0, 0])
    static let two = FieldElement51(limbs: [2, 0, 0, 0, 0])
    /// p - 1
    static let minusOne = FieldElement51(limbs: [
        2_251_799_813_685_228, 2_251_799_813_685_247, 2_251_799_813_685_247,
        2_251_799_813_685_247, 2_251_799_813_685_247,
    ])

    // MARK: Arithmetic

    static func + (lhs: FieldElement51, rhs: FieldElement51) -> FieldElement51 {
        FieldElement51(limbs: (0..<5).map { lhs.limbs[$0] &+ rhs.limbs[$0] })
    }

    static func - (lhs: FieldElement51, rhs: FieldElement51) -> FieldElement51 {
        // Add 16*p first so each subtraction cannot underflow.
        reduce([
            (lhs.limbs[0] &+ 36_028_797_018_963_664) &- rhs.limbs[0],
            (lhs.limbs[1] &+ 36_028_797_018_963_952) &- rhs.limbs[1],
            (lhs.limbs[2] &+ 36_028_797_018_963_952) &- rhs.limbs[2],
            (lhs.limbs[3] &+ 36_028_797_018_963_952) &- rhs.limbs[3],
            (lhs.limbs[4] &+ 36_028_797_018_963_952) &- rhs.limbs[4],
        ])
    }

    static prefix func - (value: FieldElement51) -> FieldElement51 {
        var copy = value
        copy.negate()
        return copy
    }

    mutating func negate() {
        let negated = Self.reduce([
            36_028_797_018_963_664 &- limbs[0],
            36_028_797_018_963_952 &- limbs[1],
            36_028_797_018_963_952 &- limbs[2],
            36_028_797_018_963_952 &- limbs[3],
            36_028_797_018_963_952 &- limbs[4],
        ])
        limbs = negated.limbs
    }

    static func * (lhs: FieldElement51, rhs: FieldElement51) -> FieldElement51 {
        let a = lhs.limbs
        let b = rhs.limbs
        let b1_19 = b[1] &* 19
        let b2_19 = b[2] &* 19
        let b3_19 = b[3] &* 19
        let b4_19 = b[4] &* 19

        func m(_ x: UInt64, _ y: UInt64) -> UInt128 { UInt128(x) &* UInt128(y) }

        let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19)
            + m(a[1], b4_19)
        var c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19)
            + m(a[2], b4_19)
        var c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19)
            + m(a[3], b4_19)
        var c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3])
            + m(a[4], b4_19)
        var c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3])
            + m(a[0], b[4])

        let mask: UInt64 = (1 << 51) - 1
        var out = [UInt64](repeating: 0, count: 5)

        c1 += c0 >> 51
        out[0] = UInt64(truncatingIfNeeded: c0) & mask
        c2 += c1 >> 51
        out[1] = UInt64(truncatingIfNeeded: c1) & mask
        c3 += c2 >> 51
        out[2] = UInt64(truncatingIfNeeded: c2) & mask
        c4 += c3 >> 51
        out[3] = UInt64(truncatingIfNeeded: c3) & mask
        let carry = UInt64(truncatingIfNeeded: c4 >> 51)
        out[4] = UInt64(truncatingIfNeeded: c4) & mask

        out[0] = out[0] &+ carry &* 19
        out[1] = out[1] &+ (out[0] >> 51)
        out[0] &= mask
        return FieldElement51(limbs: out)
    }

    func square() -> FieldElement51 { pow2k(1) }

    /// `2 * self^2`.
    func square2() -> FieldElement51 {
        var result = square()
        for i in 0..<5 {
            result.limbs[i] = result.limbs[i] &* 2
        }
        return result
    }

    /// `self^(2^k)`.
    func pow2k(_ k: UInt32) -> FieldElement51 {
        precondition(k > 0)
        var a = limbs
        var remaining = k
        let mask: UInt64 = (1 << 51) - 1

        func m(_ x: UInt64, _ y: UInt64) -> UInt128 { UInt128(x) &* UInt128(y) }

        while true {
            let a3_19 = 19 &* a[3]
            let a4_19 = 19 &* a[4]

            let c0 = m(a[0], a[0]) + 2 * (m(a[1], a4_19) + m(a[2], a3_19))
            var c1 = m(a[3], a3_19) + 2 * (m(a[0], a[1]) + m(a[2], a4_19))
            var c2 = m(a[1], a[1]) + 2 * (m(a[0], a[2]) + m(a[4], a3_19))
            var c3 = m(a[4], a4_19) + 2 * (m(a[0], a[3]) + m(a[1], a[2]))
            var c4 = m(a[2], a[2]) + 2 * (m(a[0], a[4]) + m(a[1], a[3]))

            c1 += c0 >> 51
            a[0] = UInt64(truncatingIfNeeded: c0) & mask
            c2 += c1 >> 51
            a[1] = UInt64(truncatingIfNeeded: c1) & mask
            c3 += c2 >> 51
            a[2] = UInt64(truncatingIfNeeded: c2) & mask
            c4 += c3 >> 51
            a[3] = UInt64(truncatingIfNeeded: c3) & mask
            let carry = UInt64(truncatingIfNeeded: c4 >> 51)
            a[4] = UInt64(truncatingIfNeeded: c4) & mask

            a[0] = a[0] &+ carry &* 19
            a[1] = a[1] &+ (a[0] >> 51)
            a[0] &= mask

            remaining -= 1
            if remaining == 0 { break }
        }
        return FieldElement51(limbs: a)
    }

    static func reduce(_ input: [UInt64]) -> FieldElement51 {
        let mask: UInt64 = (1 << 51) - 1
        var limbs = input
        let c0 = limbs[0] >> 51
        let c1 = limbs[1] >> 51
        let c2 = limbs[2] >> 51
        let c3 = limbs[3] >> 51
        let c4 = limbs[4] >> 51
        limbs[0] &= mask
        limbs[1] &= mask
        limbs[2] &= mask
        limbs[3] &= mask
        limbs[4] &= mask
        limbs[0] = limbs[0] &+ c4 &* 19
        limbs[1] = limbs[1] &+ c0
        limbs[2] = limbs[2] &+ c1
        limbs[3] = limbs[3] &+ c2
        limbs[4] = limbs[4] &+ c3
        return FieldElement51(limbs: limbs)
    }

    // MARK: Encoding

    /// Loads the low 255 bits of `bytes`, ignoring the top bit. The input
    /// need not be canonical.
    static func fromBytes(_ bytes: [UInt8]) -> FieldElement51 {
        precondition(bytes.count == 32)
        func load8(_ offset: Int) -> UInt64 {
            var value: UInt64 = 0
            for i in 0..<8 { value |= UInt64(bytes[offset + i]) << (8 * UInt64(i)) }
            return value
        }
        let mask: UInt64 = (1 << 51) - 1
        return FieldElement51(limbs: [
            load8(0) & mask,
            (load8(6) >> 3) & mask,
            (load8(12) >> 6) & mask,
            (load8(19) >> 1) & mask,
            (load8(24) >> 12) & mask,
        ])
    }

    /// The canonical 32-byte little-endian encoding.
    func asBytes() -> [UInt8] {
        var limbs = Self.reduce(self.limbs).limbs
        var q = (limbs[0] &+ 19) >> 51
        q = (limbs[1] &+ q) >> 51
        q = (limbs[2] &+ q) >> 51
        q = (limbs[3] &+ q) >> 51
        q = (limbs[4] &+ q) >> 51

        limbs[0] = limbs[0] &+ 19 &* q
        let mask: UInt64 = (1 << 51) - 1
        limbs[1] = limbs[1] &+ (limbs[0] >> 51)
        limbs[0] &= mask
        limbs[2] = limbs[2] &+ (limbs[1] >> 51)
        limbs[1] &= mask
        limbs[3] = limbs[3] &+ (limbs[2] >> 51)
        limbs[2] &= mask
        limbs[4] = limbs[4] &+ (limbs[3] >> 51)
        limbs[3] &= mask
        limbs[4] &= mask

        var s = [UInt8](repeating: 0, count: 32)
        s[0] = UInt8(truncatingIfNeeded: limbs[0])
        s[1] = UInt8(truncatingIfNeeded: limbs[0] >> 8)
        s[2] = UInt8(truncatingIfNeeded: limbs[0] >> 16)
        s[3] = UInt8(truncatingIfNeeded: limbs[0] >> 24)
        s[4] = UInt8(truncatingIfNeeded: limbs[0] >> 32)
        s[5] = UInt8(truncatingIfNeeded: limbs[0] >> 40)
        s[6] = UInt8(truncatingIfNeeded: (limbs[0] >> 48) | (limbs[1] << 3))
        s[7] = UInt8(truncatingIfNeeded: limbs[1] >> 5)
        s[8] = UInt8(truncatingIfNeeded: limbs[1] >> 13)
        s[9] = UInt8(truncatingIfNeeded: limbs[1] >> 21)
        s[10] = UInt8(truncatingIfNeeded: limbs[1] >> 29)
        s[11] = UInt8(truncatingIfNeeded: limbs[1] >> 37)
        s[12] = UInt8(truncatingIfNeeded: (limbs[1] >> 45) | (limbs[2] << 6))
        s[13] = UInt8(truncatingIfNeeded: limbs[2] >> 2)
        s[14] = UInt8(truncatingIfNeeded: limbs[2] >> 10)
        s[15] = UInt8(truncatingIfNeeded: limbs[2] >> 18)
        s[16] = UInt8(truncatingIfNeeded: limbs[2] >> 26)
        s[17] = UInt8(truncatingIfNeeded: limbs[2] >> 34)
        s[18] = UInt8(truncatingIfNeeded: limbs[2] >> 42)
        s[19] = UInt8(truncatingIfNeeded: (limbs[2] >> 50) | (limbs[3] << 1))
        s[20] = UInt8(truncatingIfNeeded: limbs[3] >> 7)
        s[21] = UInt8(truncatingIfNeeded: limbs[3] >> 15)
        s[22] = UInt8(truncatingIfNeeded: limbs[3] >> 23)
        s[23] = UInt8(truncatingIfNeeded: limbs[3] >> 31)
        s[24] = UInt8(truncatingIfNeeded: limbs[3] >> 39)
        s[25] = UInt8(truncatingIfNeeded: (limbs[3] >> 47) | (limbs[4] << 4))
        s[26] = UInt8(truncatingIfNeeded: limbs[4] >> 4)
        s[27] = UInt8(truncatingIfNeeded: limbs[4] >> 12)
        s[28] = UInt8(truncatingIfNeeded: limbs[4] >> 20)
        s[29] = UInt8(truncatingIfNeeded: limbs[4] >> 28)
        s[30] = UInt8(truncatingIfNeeded: limbs[4] >> 36)
        s[31] = UInt8(truncatingIfNeeded: limbs[4] >> 44)
        return s
    }

    /// Whether the canonical encoding's low bit is set: the ed25519 sign.
    var isNegative: Choice {
        Choice(asBytes()[0] & 1 == 1)
    }

    var isZero: Choice {
        Choice(asBytes().allSatisfy { $0 == 0 })
    }

    /// Constant-time field equality, compared on canonical encodings.
    static func ctEquals(_ lhs: FieldElement51, _ rhs: FieldElement51) -> Choice {
        let a = lhs.asBytes()
        let b = rhs.asBytes()
        var diff: UInt8 = 0
        for i in 0..<32 { diff |= a[i] ^ b[i] }
        return Choice(diff == 0)
    }

    /// Replaces `self` with `other` when `choice` is set.
    mutating func conditionalAssign(_ other: FieldElement51, _ choice: Choice) {
        let mask = choice.mask
        for i in 0..<5 {
            limbs[i] = (limbs[i] & ~mask) | (other.limbs[i] & mask)
        }
    }

    /// Replaces `self` with `-self` when `choice` is set.
    mutating func conditionalNegate(_ choice: Choice) {
        var negated = self
        negated.negate()
        conditionalAssign(negated, choice)
    }

    // MARK: Exponentiation

    /// `(self^(2^250 - 1), self^11)`, the shared core of inversion and the
    /// (p-5)/8 power.
    private func pow22501() -> (FieldElement51, FieldElement51) {
        let t0 = square()
        let t1 = t0.square().square()
        let t2 = self * t1
        let t3 = t0 * t2
        let t4 = t3.square()
        let t5 = t2 * t4
        let t6 = t5.pow2k(5)
        let t7 = t6 * t5
        let t8 = t7.pow2k(10)
        let t9 = t8 * t7
        let t10 = t9.pow2k(20)
        let t11 = t10 * t9
        let t12 = t11.pow2k(10)
        let t13 = t12 * t7
        let t14 = t13.pow2k(50)
        let t15 = t14 * t13
        let t16 = t15.pow2k(100)
        let t17 = t16 * t15
        let t18 = t17.pow2k(50)
        let t19 = t18 * t13
        return (t19, t3)
    }

    /// `self^(p-2)`; zero for zero.
    func invert() -> FieldElement51 {
        let (t19, t3) = pow22501()
        let t20 = t19.pow2k(5)
        return t20 * t3
    }

    /// `self^((p-5)/8)`.
    private func powP58() -> FieldElement51 {
        let (t19, _) = pow22501()
        let t20 = t19.pow2k(2)
        return self * t20
    }

    /// `(sqrt(u/v), choice)`: `choice` is set when `u/v` is square.
    ///
    /// Returns the nonnegative square root, or `sqrt(i*u/v)` when `u/v` is
    /// not square.
    static func sqrtRatioI(_ u: FieldElement51, _ v: FieldElement51) -> (Choice, FieldElement51) {
        let v3 = v.square() * v
        let v7 = v3.square() * v
        var r = (u * v3) * (u * v7).powP58()
        let check = v * r.square()

        let i = FieldElement51.sqrtM1
        let correctSignSqrt = FieldElement51.ctEquals(check, u)
        let flippedSignSqrt = FieldElement51.ctEquals(check, -u)
        let flippedSignSqrtI = FieldElement51.ctEquals(check, (-u) * i)

        let rPrime = i * r
        r.conditionalAssign(rPrime, flippedSignSqrt.or(flippedSignSqrtI))
        r.conditionalNegate(r.isNegative)
        return (correctSignSqrt.or(flippedSignSqrt), r)
    }

    /// `sqrt(1/self)`: `(choice, sqrt)` when self is a nonzero square.
    func invsqrt() -> (Choice, FieldElement51) {
        FieldElement51.sqrtRatioI(.one, self)
    }

    // MARK: Constants

    /// `sqrt(-1)`.
    static let sqrtM1 = FieldElement51(limbs: [
        1_718_705_420_411_056, 234_908_883_556_509, 2_233_514_472_574_048,
        2_117_202_627_021_982, 765_476_049_583_133,
    ])

    /// The Edwards curve `d = -121665/121666`.
    static let edwardsD = FieldElement51(limbs: [
        929_955_233_495_203, 466_365_720_129_213, 1_662_059_464_998_953,
        2_033_849_074_728_123, 1_442_794_654_840_575,
    ])

    /// `2*d`.
    static let edwardsD2 = FieldElement51(limbs: [
        1_859_910_466_990_425, 932_731_440_258_426, 1_072_319_116_312_658,
        1_815_898_335_770_999, 633_789_495_995_903,
    ])

    /// `(1 - d)^2`.
    static let oneMinusDSquared = FieldElement51(limbs: [
        1_136_626_929_484_150, 1_998_550_399_581_263, 496_427_632_559_748,
        118_527_312_129_759, 45_110_755_273_534,
    ])

    /// `(d - 1)^2`.
    static let dMinusOneSquared = FieldElement51(limbs: [
        1_507_062_230_895_904, 1_572_317_787_530_805, 683_053_064_812_840,
        317_374_165_784_489, 1_572_899_562_415_810,
    ])

    /// `sqrt(a*d - 1)` for `a = -1`.
    static let sqrtADMinusOne = FieldElement51(limbs: [
        2_241_493_124_984_347, 425_987_919_032_274, 2_207_028_919_301_688,
        1_220_490_630_685_848, 974_799_131_293_748,
    ])

    /// `1/sqrt(a - d)` for `a = -1`.
    static let invsqrtAMinusD = FieldElement51(limbs: [
        278_908_739_862_762, 821_645_201_101_625, 8_113_234_426_968,
        1_777_959_178_193_151, 2_118_520_810_568_447,
    ])
}

extension FieldElement51: Equatable {
    /// Field equality, not limb equality: representations are not canonical.
    static func == (lhs: FieldElement51, rhs: FieldElement51) -> Bool {
        ctEquals(lhs, rhs).boolValue
    }
}
