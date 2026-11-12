import XCTest

@testable import XChat

/// Fixed vectors from FIPS-197 and NIST CAVS, the same sets the reference
/// implementations are validated against.
final class AES128GCMTests: XCTestCase {
  private func hex(_ string: String) -> [UInt8] {
    try! Hex.decode(string)
  }

  // NIST CAVS gcmEncryptExtIV128.rsp vectors, covering empty payloads,
  // partial plaintext blocks, and associated data.
  func testGCMCAVS() throws {
    let vectors:
      [(
        key: String, nonce: String, plaintext: String, aad: String, ciphertext: String, tag: String
      )] = [
        (
          "11754cd72aec309bf52f7687212e8957", "3c819d9a9bed087615030b65",
          "", "",
          "", "250327c674aaf477aef2675748cf6971"
        ),
        (
          "7fddb57453c241d03efbed3ac44e371c", "ee283a3fc75575e33efd4887",
          "d5de42b461646c255c87bd2962d3b9a2", "",
          "2ccda4a5415cb91e135c2a0f78c9b2fd", "b36d1df9b9d5e596f83e8b7f52971cb3"
        ),
        (
          "c939cc13397c1d37de6ae0e1cb7c423c", "b3d8cc017cbb89b39e0f67e2",
          "c3b3c41f113a31b73d9a5cd432103069", "24825602bd12a984e0092d3e448eda5f",
          "93fe7d9e9bfd10348a5606e5cafa7354", "0032a1dc85f1c9786925a2e71d8272dd"
        ),
        (
          "fe9bb47deb3a61e423c2231841cfd1fb", "4d328eb776f500a2f7fb47aa",
          "f1cc3818e421876bb6b8bbd6c9", "",
          "b88c5c1977b35b517b0aeae967", "43fd4727fe5cdb4b5b42818dea7ef8c9"
        ),
        (
          "2fb45e5b8f993a2bfebc4b15b533e0b4", "5b05755f984d2b90f94b8027",
          "", "e85491b2202caf1d7dce03b97e09331c32473941",
          "", "c75b7832b2a2d9bd827412b6ef5769db"
        ),
        (
          "e47e1e3a95627418ed659452a3c92d45", "78adcf3f732dd3787cb5490b",
          "801efcab1e329a536a7b506c4a7509ec",
          "41913a6c5c4dddae06f3c0f68e8ece139ca902fe340a820e7c40d895b35e8f4cba7809c7eed0b2b7ad45c6d152ec3053",
          "6751a4a5e0cc3c0f46cb5540937efde8", "7b07d21a4cbadeedcadce817d9ab81be"
        ),
        (
          "11f47551416154006bf89e7594ea2082", "d546fcd3ff2a6a17461e9e94",
          "d3783a3d7a1e091f9cb647bf45604457",
          "49efdce48e821eb14eca5f1dd661f8b6b9a5a6917b08ec9486c29124ef1e7a9af2217494eecad3d8eef9fc22d29ce18d92006de1588c3b06f8db9fe809bede40908cef4f46d2c4b6f92ff5a8304362749143dab266de45bf5b4a",
          "e97988a6645b93a32e8296bb1dbcb8f9", "399345f974a82a2a75007c84aa08dc1a"
        ),
      ]

    for vector in vectors {
      let gcm = AES128GCM(key: hex(vector.key))
      let sealed = try gcm.seal(
        nonce: hex(vector.nonce),
        plaintext: hex(vector.plaintext),
        authenticatedData: hex(vector.aad)
      )
      XCTAssertEqual(sealed, hex(vector.ciphertext) + hex(vector.tag))

      let opened = try gcm.open(
        nonce: hex(vector.nonce),
        ciphertextAndTag: sealed,
        authenticatedData: hex(vector.aad)
      )
      XCTAssertEqual(opened, hex(vector.plaintext))
    }
  }

  /// Tampered ciphertext must fail, and the failure must not leak plaintext.
  func testGCMRejectsTampering() throws {
    let gcm = AES128GCM(key: hex("7fddb57453c241d03efbed3ac44e371c"))
    let nonce = hex("ee283a3fc75575e33efd4887")
    let sealed = try gcm.seal(nonce: nonce, plaintext: hex("d5de42b461646c255c87bd2962d3b9a2"))

    var tampered = sealed
    tampered[0] ^= 0xaa
    XCTAssertThrowsError(try gcm.open(nonce: nonce, ciphertextAndTag: tampered))
    XCTAssertThrowsError(
      try gcm.open(nonce: nonce, ciphertextAndTag: [UInt8](repeating: 0, count: 10)))
  }

  // NIST CAVS vectors for non-96-bit nonces, where J0 is GHASH of the IV.
  // This is the path the 16-byte ECIES nonce takes.
  func testGCMExtendedIV() throws {
    // IVlen = 1024
    let gcm1024 = AES128GCM(key: hex("71eebc49c8fb773b2224eaff3ad68714"))
    let nonce1024 = hex(
      "07e961e67784011f72faafd95b0eb64089c8de15ad685ec57e63d56e679d3e20"
        + "2b18b75fcbbec3185ffc41653bc2ac4ae6ae8be8c85636f353a9d19a86100d0b"
        + "d035cc6bdefcab4318ac7b1a08b819427ad8f6abc782466c6ebd4d6a0dd76e78"
        + "389b0a2a66506bb85f038ffc1da220c24f3817c7b2d02c5e8fc5e7e3be5074bc"
    )
    let sealed1024 = try gcm1024.seal(
      nonce: nonce1024, plaintext: hex("705da82292143d2c949dc4ba014f6396"))
    XCTAssertEqual(
      sealed1024, hex("032363cf0828a03553478bec0f51f372c681b2c568feaa21900bc44b86aeb946"))
  }

  /// 16-byte nonces must round trip, and differ from the 12-byte-J0 form.
  func testGCM16ByteIVRoundTrip() throws {
    let key = [UInt8](0..<16).map { _ in UInt8.random(in: 0...255) }
    let nonce = [UInt8](0..<16).map { _ in UInt8.random(in: 0...255) }
    let plaintext = [UInt8]("sixteen byte nonce payload".utf8)
    let gcm = AES128GCM(key: key)
    let sealed = try gcm.seal(nonce: nonce, plaintext: plaintext)
    XCTAssertEqual(try gcm.open(nonce: nonce, ciphertextAndTag: sealed), plaintext)
    XCTAssertEqual(sealed.count, plaintext.count + 16)
  }
}
