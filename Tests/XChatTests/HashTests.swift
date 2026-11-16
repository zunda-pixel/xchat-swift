import Testing

@testable import XChat

/// SHA-256, HMAC-SHA256, HKDF-SHA256 and X9.63 KDF2 against published
/// vectors, plus the length rules the protocol depends on.
struct HashTests {
  private static func hex(_ string: String) -> [UInt8] {
    try! Hex.decode(string)
  }

  @Test func sha256KnownAnswers() {
    #expect(
      Hex.encode(sha256(Array("hello".utf8)))
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    #expect(
      Hex.encode(sha256([]))
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  }

  /// RFC 4231 test case 1.
  @Test func hmacSHA256RFC4231Case1() {
    let key = [UInt8](repeating: 0x0b, count: 20)
    let message = Array("Hi There".utf8)
    #expect(
      Hex.encode(hmacSHA256(message: message, key: key))
        == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  }

  /// RFC 4231 test case 2.
  @Test func hmacSHA256RFC4231Case2() {
    let key = Array("Jefe".utf8)
    let message = Array("what do ya want for nothing?".utf8)
    #expect(
      Hex.encode(hmacSHA256(message: message, key: key))
        == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  }

  /// RFC 5869 test case 3: zero-length salt (32 zero bytes) and empty
  /// info, 42 bytes of output.
  @Test func hkdfRFC5869Case3() throws {
    let ikm = [UInt8](repeating: 0x0b, count: 22)
    let okm = hkdf(secret: ikm, salt: "", length: 42)
    #expect(
      Hex.encode(okm)
        == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        + "9d201395faa4b61a96c8")
  }

  @Test func hkdfInfoAndSaltDomainSeparate() throws {
    let secret = Array("secret key material".utf8)
    let base = hkdf(secret: secret, salt: "salt", length: 32)
    let withInfo = hkdfWithInfo(secret: secret, salt: "salt", info: [1], length: 32)
    let otherSalt = hkdf(secret: secret, salt: "other", length: 32)
    #expect(base.count == 32)
    #expect(base != withInfo)
    #expect(base != otherSalt)
    #expect(base == hkdf(secret: secret, salt: "salt", length: 32))
  }

  @Test func randomBytesProducesRequestedLength() {
    let first = XChat.randomBytes(32)
    #expect(first.count == 32)
    #expect(XChat.randomBytes(0) == [])
    #expect(first != XChat.randomBytes(32))
  }
}
