import Crypto

/// Cryptographically secure random bytes from the system random source.
func juiceboxRandomBytes(_ length: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) }
}

extension Scalar52 {
    /// A uniformly random scalar: 64 random bytes reduced modulo ℓ.
    static func random() -> Scalar52 {
        fromBytesWide(juiceboxRandomBytes(64))
    }

    /// Constant-time scalar equality.
    static func ctEquals(_ lhs: Scalar52, _ rhs: Scalar52) -> Choice {
        let a = lhs.asBytes()
        let b = rhs.asBytes()
        var difference: UInt8 = 0
        for i in 0..<32 {
            difference |= a[i] ^ b[i]
        }
        return Choice(difference == 0)
    }
}
