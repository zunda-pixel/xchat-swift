/// Shamir secret sharing over a type that supports addition and scalar
/// multiplication, matching the Juicebox share indices (1...count).
protocol SecretShareable: Sendable {
    static var additiveIdentity: Self { get }
    static func random() -> Self
    static func adding(_ lhs: Self, _ rhs: Self) -> Self
    static func multiplied(_ value: Self, by scalar: Scalar52) -> Self
}

struct SecretShare<Secret: SecretShareable>: Sendable {
    let index: UInt32
    let secret: Secret
}

enum SecretSharingError: Error, Equatable {
    case duplicateShares
}

extension Scalar52: SecretShareable {
    static var additiveIdentity: Scalar52 { .zero }
    static func adding(_ lhs: Scalar52, _ rhs: Scalar52) -> Scalar52 { lhs + rhs }
    static func multiplied(_ value: Scalar52, by scalar: Scalar52) -> Scalar52 { value * scalar }
}

extension RistrettoPoint: SecretShareable {
    static var additiveIdentity: RistrettoPoint { .identity }
    static func random() -> RistrettoPoint {
        fromUniformBytes(juiceboxRandomBytes(64))
    }
    static func adding(_ lhs: RistrettoPoint, _ rhs: RistrettoPoint) -> RistrettoPoint {
        lhs + rhs
    }
    static func multiplied(_ value: RistrettoPoint, by scalar: Scalar52) -> RistrettoPoint {
        value.scalarMultiply(scalar)
    }
}

/// The scalar for a share index: the index in the low four little-endian
/// bytes.
func shareIndexScalar(_ index: UInt32) -> Scalar52 {
    var bytes = [UInt8](repeating: 0, count: 32)
    bytes[0] = UInt8(truncatingIfNeeded: index)
    bytes[1] = UInt8(truncatingIfNeeded: index >> 8)
    bytes[2] = UInt8(truncatingIfNeeded: index >> 16)
    bytes[3] = UInt8(truncatingIfNeeded: index >> 24)
    return Scalar52.fromBytes(bytes)
}

/// Distributes `secret` into `count` shares; any `threshold` recover it.
func createShares<Secret: SecretShareable>(
    secret: Secret, threshold: Int, count: Int, random: () -> Secret
) -> [SecretShare<Secret>] {
    precondition(threshold > 0 && count > 0 && threshold <= count)
    var coefficients: [Secret] = []
    if threshold > 1 {
        for _ in 1..<threshold {
            coefficients.append(random())
        }
    }
    return (1...count).map { index in
        let x = shareIndexScalar(UInt32(index))
        var value = Secret.additiveIdentity
        for coefficient in coefficients {
            value = Secret.multiplied(Secret.adding(value, coefficient), by: x)
        }
        value = Secret.adding(value, secret)
        return SecretShare(index: UInt32(index), secret: value)
    }
}

/// Recovers the secret by Lagrange interpolation at zero.
func recoverSecret<Secret: SecretShareable>(
    _ shares: [SecretShare<Secret>]
) throws -> Secret {
    var result = Secret.additiveIdentity
    for (i, share) in shares.enumerated() {
        var numerator = Scalar52.one
        var denominator = Scalar52.one
        let xi = shareIndexScalar(share.index)
        for (j, other) in shares.enumerated() where j != i {
            let xj = shareIndexScalar(other.index)
            numerator = numerator * xj
            denominator = denominator * (xj - xi)
        }
        guard !denominator.isZero else { throw SecretSharingError.duplicateShares }
        let coefficient = numerator * denominator.invert()
        result = Secret.adding(result, Secret.multiplied(share.secret, by: coefficient))
    }
    return result
}
