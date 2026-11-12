import XCTest

@testable import XChat

/// SHA-256, HMAC-SHA256, HKDF-SHA256 and X9.63 KDF2 against published
/// vectors, plus the length rules the protocol depends on.
final class HashTests: XCTestCase {
    private static func hex(_ string: String) -> [UInt8] {
        try! Hex.decode(string)
    }

    func testSHA256KnownAnswers() {
        XCTAssertEqual(
            Hex.encode(sha256(Array("hello".utf8))),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        XCTAssertEqual(
            Hex.encode(sha256([])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    /// RFC 4231 test case 1.
    func testHMACSHA256RFC4231Case1() {
        let key = [UInt8](repeating: 0x0b, count: 20)
        let message = Array("Hi There".utf8)
        XCTAssertEqual(
            Hex.encode(hmacSHA256(message: message, key: key)),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    }

    /// RFC 4231 test case 2.
    func testHMACSHA256RFC4231Case2() {
        let key = Array("Jefe".utf8)
        let message = Array("what do ya want for nothing?".utf8)
        XCTAssertEqual(
            Hex.encode(hmacSHA256(message: message, key: key)),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    }

    /// RFC 5869 test case 3: zero-length salt (32 zero bytes) and empty
    /// info, 42 bytes of output.
    func testHKDFRFC5869Case3() throws {
        let ikm = [UInt8](repeating: 0x0b, count: 22)
        let okm = try hkdf(secret: ikm, salt: "", length: 42)
        XCTAssertEqual(
            Hex.encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                + "9d201395faa4b61a96c8")
    }

    func testHKDFInfoAndSaltDomainSeparate() throws {
        let secret = Array("secret key material".utf8)
        let base = try hkdf(secret: secret, salt: "salt", length: 32)
        let withInfo = try hkdfWithInfo(secret: secret, salt: "salt", info: [1], length: 32)
        let otherSalt = try hkdf(secret: secret, salt: "other", length: 32)
        XCTAssertEqual(base.count, 32)
        XCTAssertNotEqual(base, withInfo)
        XCTAssertNotEqual(base, otherSalt)
        XCTAssertEqual(base, try hkdf(secret: secret, salt: "salt", length: 32))
    }

    func testHKDFLengthLimit() {
        XCTAssertThrowsError(try hkdf(secret: [1], salt: "s", length: 8161)) { error in
            let error = error as? XChatError
            XCTAssertEqual(error?.kind, .internalError)
            XCTAssertEqual(error?.message, "Requested length 8161 exceeds maximum 8160")
        }
        XCTAssertNoThrow(try hkdf(secret: [1], salt: "s", length: 8160))
    }

    func testKDF2LengthAndPrefix() {
        let secret = [UInt8](repeating: 7, count: 32)
        let info = Array("ephemeral".utf8)
        XCTAssertEqual(kdf2SHA256(sharedSecret: secret, sharedInfo: info, length: 0), [])
        XCTAssertEqual(kdf2SHA256(sharedSecret: secret, sharedInfo: info, length: 16).count, 16)
        let full = kdf2SHA256(sharedSecret: secret, sharedInfo: info, length: 64)
        XCTAssertEqual(full.count, 64)
        // KDF2 is a truncation of the same stream.
        XCTAssertEqual(
            Array(full.prefix(16)),
            kdf2SHA256(sharedSecret: secret, sharedInfo: info, length: 16))
        // The counter is a 4-byte big-endian value starting at 1, so one
        // round over an empty secret and info is SHA-256 of just the counter.
        XCTAssertEqual(
            kdf2SHA256(sharedSecret: [], sharedInfo: [], length: 32),
            sha256([0x00, 0x00, 0x00, 0x01]))
        // Different shared info gives different output.
        XCTAssertNotEqual(
            kdf2SHA256(sharedSecret: secret, sharedInfo: Array("other".utf8), length: 32),
            kdf2SHA256(sharedSecret: secret, sharedInfo: info, length: 32))
    }

    func testRandomBytes() {
        let first = randomBytes(32)
        XCTAssertEqual(first.count, 32)
        XCTAssertEqual(randomBytes(0), [])
        XCTAssertNotEqual(first, randomBytes(32))
    }
}
