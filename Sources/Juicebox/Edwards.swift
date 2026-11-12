/// A point on the twisted Edwards curve `-x^2 + y^2 = 1 + d x^2 y^2`,
/// in extended coordinates `(X:Y:Z:T)` with `x = X/Z`, `y = Y/Z`,
/// and `xy = T/Z`.
struct EdwardsPoint: Sendable {
    var x: FieldElement51
    var y: FieldElement51
    var z: FieldElement51
    var t: FieldElement51

    static let identity = EdwardsPoint(x: .zero, y: .one, z: .one, t: .zero)

    /// The Ed25519 basepoint, which is also the Ristretto basepoint.
    static let basepoint = EdwardsPoint(
        x: FieldElement51(limbs: [
            1_738_742_601_995_546, 1_146_398_526_822_698, 2_070_867_633_025_821,
            562_264_141_797_630, 587_772_402_128_613,
        ]),
        y: FieldElement51(limbs: [
            1_801_439_850_948_184, 1_351_079_888_211_148, 450_359_962_737_049,
            900_719_925_474_099, 1_801_439_850_948_198,
        ]),
        z: .one,
        t: FieldElement51(limbs: [
            1_841_354_044_333_475, 16_398_895_984_059, 755_974_180_946_558,
            900_171_276_175_154, 1_821_297_809_914_039,
        ]))

    // MARK: Arithmetic

    func double() -> EdwardsPoint {
        let xx = x.square()
        let yy = y.square()
        let zz2 = z.square2()
        let xPlusYSquared = (x + y).square()
        let yyPlusXX = yy + xx
        let yyMinusXX = yy - xx
        let cx = xPlusYSquared - yyPlusXX
        let cy = yyPlusXX
        let cz = yyMinusXX
        let ct = zz2 - yyMinusXX
        return EdwardsPoint(x: cx * ct, y: cy * cz, z: cz * ct, t: cx * cy)
    }

    static func + (lhs: EdwardsPoint, rhs: EdwardsPoint) -> EdwardsPoint {
        let a = (lhs.y - lhs.x) * (rhs.y - rhs.x)
        let b = (lhs.y + lhs.x) * (rhs.y + rhs.x)
        let c = lhs.t * FieldElement51.edwardsD2 * rhs.t
        let d = (lhs.z * rhs.z) * .two
        let e = b - a
        let f = d - c
        let g = d + c
        let h = b + a
        return EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)
    }

    static func - (lhs: EdwardsPoint, rhs: EdwardsPoint) -> EdwardsPoint {
        lhs + (-rhs)
    }

    static prefix func - (point: EdwardsPoint) -> EdwardsPoint {
        EdwardsPoint(x: -point.x, y: point.y, z: point.z, t: -point.t)
    }

    mutating func conditionalAssign(_ other: EdwardsPoint, _ choice: Choice) {
        x.conditionalAssign(other.x, choice)
        y.conditionalAssign(other.y, choice)
        z.conditionalAssign(other.z, choice)
        t.conditionalAssign(other.t, choice)
    }

    /// Multiplies by a scalar with a fixed-order, branch-free double-and-add:
    /// every bit doubles and conditionally adds, so the work does not depend
    /// on the scalar's value.
    func scalarMultiply(_ scalar: Scalar52) -> EdwardsPoint {
        var result = EdwardsPoint.identity
        for bit in stride(from: 259, through: 0, by: -1) {
            result = result.double()
            var addend = EdwardsPoint.identity
            let setBit = (scalar.limbs[bit / 52] >> UInt64(bit % 52)) & 1
            addend.conditionalAssign(self, Choice(mask: setBit))
            result = result + addend
        }
        return result
    }

    /// Whether this is the neutral element: `X = 0` and `Y = Z`.
    var isIdentity: Choice {
        x.isZero.and(FieldElement51.ctEquals(y, z))
    }

    // MARK: Encoding

    /// The 32-byte compressed Edwards encoding: `y` with the sign of `x` in
    /// the top bit.
    func compress() -> [UInt8] {
        let recip = z.invert()
        let affineX = x * recip
        let affineY = y * recip
        var bytes = affineY.asBytes()
        if affineX.isNegative.boolValue {
            bytes[31] |= 0x80
        }
        return bytes
    }

    /// Decodes a compressed Edwards point, rejecting non-canonical `y` and
    /// the sign bit that no point uses.
    static func decompress(_ bytes: [UInt8]) -> EdwardsPoint? {
        precondition(bytes.count == 32)
        let affineY = FieldElement51.fromBytes(bytes)
        guard affineY.asBytes() == bytes else { return nil }
        let sign = (bytes[31] & 0x80) != 0

        let ySquared = affineY.square()
        let u = ySquared - .one
        let v = FieldElement51.edwardsD * ySquared + .one
        let (isSquare, root) = FieldElement51.sqrtRatioI(u, v)
        guard isSquare.boolValue else { return nil }

        var affineX = root
        if affineX.isZero.boolValue && sign { return nil }
        if affineX.isNegative.boolValue != sign {
            affineX = -affineX
        }
        return EdwardsPoint(x: affineX, y: affineY, z: .one, t: affineX * affineY)
    }
}
