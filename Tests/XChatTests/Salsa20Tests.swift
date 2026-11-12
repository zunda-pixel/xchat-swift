import XCTest

@testable import XChat

/// Salsa20, HSalsa20 and XSalsa20 against the reference crate's own test
/// vectors (eSTREAM-derived), including its offset test, sampled.
final class Salsa20Tests: XCTestCase {
    private static func hex(_ string: String) -> [UInt8] {
        try! Hex.decode(string)
    }

    private static let zeroKey = hex(
        "0000000000000000000000000000000000000000000000000000000000000000")
    private static let keyLong = hex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    private static let ivLong = hex("0301040105090206")
    private static let expectedLong = hex(
        "6ebcbdbf76fccc64ab05542bee8a67cb"
            + "c28fa2e141fbefbb3a2f9b221909c8d7"
            + "d4295258cb539770dd24d7ac3443769f"
            + "fa27a50e60644264dc8b6b612683372e"
            + "085d0a12bf240b189ce2b78289862b56"
            + "fdc9fcffc33bef9325a2e81b98fb3fb9"
            + "aa04cf434615ceffeb985c1cb08d8440"
            + "e90b1d56ddeaea16d9e15affff1f698c"
            + "483c7a466af1fe062574adfd2b06a62b"
            + "4d98440719ea776385c470349a7ed696"
            + "9583463ed5d26b8fefccb205da0f5bfa"
            + "98c77812fe756b09eacc282aa42f4baf"
            + "a79633189046e2b20f35b3e0e54aa3b9"
            + "29e23c0f47dc7bcd4f928b2a9764be7d"
            + "4b8a50f980a50b35ad8087375e0c556e"
            + "cbe6a7161e8653ce9391e1e6710ed4f1")

    func testSalsa20Key1Iv0() {
        var cipher = Salsa20(
            key: Self.hex(
                "8000000000000000000000000000000000000000000000000000000000000000"),
            nonce: Self.hex("0000000000000000"))
        var zeros = [UInt8](repeating: 0, count: 64)
        cipher.xor(into: &zeros)
        XCTAssertEqual(
            zeros,
            Self.hex(
                "e3be8fdd8beca2e3ea8ef9475b29a6e7"
                    + "003951e1097a5c38d23b7a5fad9f6844"
                    + "b22c97559e2723c7cbbd3fe4fc8d9a07"
                    + "44652a83e72a9c461876af4d7ef1a117"))
    }

    func testSalsa20Key0Iv1() {
        var cipher = Salsa20(key: Self.zeroKey, nonce: Self.hex("8000000000000000"))
        var zeros = [UInt8](repeating: 0, count: 64)
        cipher.xor(into: &zeros)
        XCTAssertEqual(
            zeros,
            Self.hex(
                "2aba3dc45b4947007b14c851cd694456"
                    + "b303ad59a465662803006705673d6c3e"
                    + "29f1d3510dfc0405463c03414e0e07e3"
                    + "59f1f1816c68b2434a19d3eee0464873"))
    }

    func testSalsa20Key0IvHi() {
        var cipher = Salsa20(key: Self.zeroKey, nonce: Self.hex("0000000000000001"))
        var zeros = [UInt8](repeating: 0, count: 64)
        cipher.xor(into: &zeros)
        XCTAssertEqual(
            zeros,
            Self.hex(
                "b47f96aa96786135297a3c4ec56a613d"
                    + "0b80095324ff43239d684c57ffe42e1c"
                    + "44f3cc011613db6cdc880999a1e65aed"
                    + "1287fcb11c839c37120765afa73e5075"))
    }

    func testSalsa20LongKeystream() {
        var cipher = Salsa20(key: Self.keyLong, nonce: Self.ivLong)
        var zeros = [UInt8](repeating: 0, count: 256)
        cipher.xor(into: &zeros)
        XCTAssertEqual(zeros, Self.expectedLong)
    }

    /// The reference crate's exhaustive offset test, sampled at interesting
    /// seek positions (block boundaries ±1, mid-block) and split points.
    func testSalsa20Offsets() {
        for idx in [0, 1, 63, 64, 65, 130, 191] {
            for middle in stride(from: idx, through: 256, by: 37) {
                for last in stride(from: middle + 1, through: 256, by: 53) {
                    var cipher = Salsa20(key: Self.keyLong, nonce: Self.ivLong)
                    var buf = [UInt8](repeating: 0, count: 256)
                    cipher.seek(to: UInt64(idx))
                    cipher.xor(into: &buf, range: idx..<middle)
                    cipher.xor(into: &buf, range: middle..<last)
                    XCTAssertEqual(Array(buf[idx..<last]), Array(Self.expectedLong[idx..<last]))
                }
            }
        }
    }

    func testXSalsa20EncryptZeros() {
        var cipher = Salsa20.xsalsa(
            key: Array("this is 32-byte key for xsalsa20".utf8),
            nonce: Array("24-byte nonce for xsalsa".utf8))
        var zeros = [UInt8](repeating: 0, count: 64)
        cipher.xor(into: &zeros)
        XCTAssertEqual(
            zeros,
            Self.hex(
                "4848297feb1fb52fb66d81609bd547fa"
                    + "bcbe7026edc8b5e5e449d088bfa69c08"
                    + "8f5d8da1d791267c2c195a7f8cae9c4b"
                    + "4050d08ce6d3a151ec265f3a58e47648"))
    }

    func testXSalsa20EncryptHelloWorld() {
        var cipher = Salsa20.xsalsa(
            key: Array("this is 32-byte key for xsalsa20".utf8),
            nonce: Array("24-byte nonce for xsalsa".utf8))
        var message = Array("Hello world!".utf8)
        cipher.xor(into: &message)
        XCTAssertEqual(message, Self.hex("002d4513843fc240c401e541"))
    }
}
