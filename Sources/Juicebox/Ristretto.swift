import Crypto

/// The Ristretto255 group, represented by an Edwards point in the prime-order
/// subgroup. Compression and decompression implement the canonical Ristretto
/// encoding, and `fromUniformBytes` is the one-way map.
struct RistrettoPoint: Sendable {
    var edwards: EdwardsPoint

    static let identity = RistrettoPoint(edwards: .identity)
    static let basepoint = RistrettoPoint(edwards: .basepoint)

    // MARK: Arithmetic

    static func + (lhs: RistrettoPoint, rhs: RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(edwards: lhs.edwards + rhs.edwards)
    }

    static func - (lhs: RistrettoPoint, rhs: RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(edwards: lhs.edwards - rhs.edwards)
    }

    static prefix func - (point: RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(edwards: -point.edwards)
    }

    func double() -> RistrettoPoint {
        RistrettoPoint(edwards: edwards.double())
    }

    func scalarMultiply(_ scalar: Scalar52) -> RistrettoPoint {
        RistrettoPoint(edwards: edwards.scalarMultiply(scalar))
    }

    static func * (point: RistrettoPoint, scalar: Scalar52) -> RistrettoPoint {
        point.scalarMultiply(scalar)
    }

    static func * (scalar: Scalar52, point: RistrettoPoint) -> RistrettoPoint {
        point.scalarMultiply(scalar)
    }

    /// Two points are equal when they are in the same coset: `X1/Y1 = X2/Y2`
    /// or `X1/X2 = Y1/Y2`.
    static func ctEquals(_ lhs: RistrettoPoint, _ rhs: RistrettoPoint) -> Choice {
        let x1y2 = lhs.edwards.x * rhs.edwards.y
        let y1x2 = lhs.edwards.y * rhs.edwards.x
        let x1x2 = lhs.edwards.x * rhs.edwards.x
        let y1y2 = lhs.edwards.y * rhs.edwards.y
        return FieldElement51.ctEquals(x1y2, y1x2)
            .or(FieldElement51.ctEquals(x1x2, y1y2))
    }

    // MARK: Encoding

    func compress() -> [UInt8] {
        var x = edwards.x
        var y = edwards.y
        let z = edwards.z
        let t = edwards.t

        let u1 = (z + y) * (z - y)
        let u2 = x * y
        let (_, invsqrt) = (u1 * u2.square()).invsqrt()
        let i1 = invsqrt * u1
        let i2 = invsqrt * u2
        let zInverse = i1 * (i2 * t)
        var denominatorInverse = i2

        let iX = x * FieldElement51.sqrtM1
        let iY = y * FieldElement51.sqrtM1
        let ristrettoMagic = FieldElement51.invsqrtAMinusD
        let enchantedDenominator = i1 * ristrettoMagic

        let rotate = (t * zInverse).isNegative
        x.conditionalAssign(iY, rotate)
        y.conditionalAssign(iX, rotate)
        denominatorInverse.conditionalAssign(enchantedDenominator, rotate)

        y.conditionalNegate((x * zInverse).isNegative)

        var s = denominatorInverse * (z - y)
        s.conditionalNegate(s.isNegative)
        return s.asBytes()
    }

    static func decompress(_ bytes: [UInt8]) -> RistrettoPoint? {
        precondition(bytes.count == 32)
        let s = FieldElement51.fromBytes(bytes)
        guard s.asBytes() == bytes, !s.isNegative.boolValue else { return nil }

        let one = FieldElement51.one
        let sSquared = s.square()
        let u1 = one - sSquared
        let u2 = one + sSquared
        let u2Squared = u2.square()
        let v = (-FieldElement51.edwardsD) * u1.square() - u2Squared
        let (isSquare, invsqrt) = (v * u2Squared).invsqrt()

        let dX = invsqrt * u2
        let dY = invsqrt * (dX * v)
        var x = (s + s) * dX
        x.conditionalNegate(x.isNegative)
        let y = u1 * dY
        let t = x * y

        guard isSquare.boolValue, !t.isNegative.boolValue, !y.isZero.boolValue else {
            return nil
        }
        return RistrettoPoint(edwards: EdwardsPoint(x: x, y: y, z: one, t: t))
    }

    // MARK: Hashing

    /// Maps 64 uniform bytes onto the group by applying the Ristretto
    /// Elligator map to each half and adding the results.
    static func fromUniformBytes(_ bytes: [UInt8]) -> RistrettoPoint {
        precondition(bytes.count == 64)
        let first = FieldElement51.fromBytes(Array(bytes[0..<32]))
        let second = FieldElement51.fromBytes(Array(bytes[32..<64]))
        return elligatorRistrettoFlavor(first) + elligatorRistrettoFlavor(second)
    }

    /// `SHA-512(input)` mapped onto the group: the OPRF's hash-to-group.
    static func hashToGroup(_ input: [UInt8]) -> RistrettoPoint {
        fromUniformBytes(Array(SHA512.hash(data: input)))
    }

    /// The Ristretto-flavoured Elligator 2 map. The result is a point whose
    /// discrete log with respect to any other point is unknown.
    private static func elligatorRistrettoFlavor(_ r0: FieldElement51) -> RistrettoPoint {
        let i = FieldElement51.sqrtM1
        let d = FieldElement51.edwardsD
        let oneMinusDSquared = FieldElement51.oneMinusDSquared
        let dMinusOneSquared = FieldElement51.dMinusOneSquared
        var c = FieldElement51.minusOne
        let one = FieldElement51.one

        let r = i * r0.square()
        let nS = (r + one) * oneMinusDSquared
        let dd = (c - d * r) * (r + d)

        let (nSOverDIsSquare, root) = FieldElement51.sqrtRatioI(nS, dd)
        var s = root
        var sPrime = s * r0
        sPrime.conditionalNegate(!sPrime.isNegative)
        s.conditionalAssign(sPrime, !nSOverDIsSquare)
        c.conditionalAssign(r, !nSOverDIsSquare)

        let nT = (c * (r - one)) * dMinusOneSquared - dd
        let sSquared = s.square()

        // A completed point: convert `((X:Z), (Y:T))` to extended coordinates.
        let cx = (s + s) * dd
        let cy = one - sSquared
        let cz = nT * FieldElement51.sqrtADMinusOne
        let ct = one + sSquared
        return RistrettoPoint(edwards: EdwardsPoint(
            x: cx * ct, y: cy * cz, z: cz * ct, t: cx * cy))
    }
}

extension RistrettoPoint: Equatable {
    static func == (lhs: RistrettoPoint, rhs: RistrettoPoint) -> Bool {
        ctEquals(lhs, rhs).boolValue
    }
}
