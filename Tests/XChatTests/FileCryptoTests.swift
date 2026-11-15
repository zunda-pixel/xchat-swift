import XCTest

@testable import XChat

/// The file wire format — `header (24B) || chunks` — through
/// `FileEncryptor`/`FileDecryptor`, including the core's cross-binding
/// media vector, framing rules, and every truncation and tampering fault.
final class FileCryptoTests: XCTestCase {
  /// The conversation key is itself the secretstream key, so the media
  /// vector decrypts with it directly.
  private static let key = TestVectors.bytes("conversation_key_b64")
  private static let vectorCiphertext = TestVectors.bytes("media_conversation_key_encrypted_b64")
  private static let vectorPlaintext = TestVectors.bytes("media_conversation_key_plaintext_b64")

  /// Asserts the closure throws `expected`.
  private func assertThrows<T>(
    _ expected: XChatError,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    XCTAssertThrowsError(try body(), message(), file: file, line: line) { error in
      XCTAssertEqual(error as? XChatError, expected, message(), file: file, line: line)
    }
  }

  /// Asserts the closure throws `fault` for a file under a key the caller
  /// holds.
  private func assertThrows<T>(
    _ fault: XChatError.FileFault,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    assertThrows(
      .decryption(.file(fault, mediaHashKey: nil)), message(), file: file, line: line, body)
  }

  // MARK: Cross-binding vector

  /// The core's media ciphertext decrypts through the file layer whether
  /// fed whole, one byte at a time, or in 700-byte pieces.
  func testVectorDecryptsThroughFileDecryptor() throws {
    XCTAssertEqual(Self.vectorCiphertext.count, 1558)
    XCTAssertEqual(Self.vectorPlaintext.count, 1500)

    XCTAssertEqual(
      try decryptFile(key: Self.key, ciphertext: Self.vectorCiphertext),
      Self.vectorPlaintext)

    var byteWise = try FileDecryptor(key: Self.key)
    var byteWisePlaintext: [UInt8] = []
    for byte in Self.vectorCiphertext {
      byteWisePlaintext += try byteWise.push([byte])
    }
    byteWisePlaintext += try byteWise.finish()
    XCTAssertEqual(byteWisePlaintext, Self.vectorPlaintext)

    var chunked = try FileDecryptor(key: Self.key)
    var chunkedPlaintext: [UInt8] = []
    var offset = 0
    while offset < Self.vectorCiphertext.count {
      let end = min(offset + 700, Self.vectorCiphertext.count)
      chunkedPlaintext += try chunked.push(Array(Self.vectorCiphertext[offset..<end]))
      offset = end
    }
    chunkedPlaintext += try chunked.finish()
    XCTAssertEqual(chunkedPlaintext, Self.vectorPlaintext)
  }

  /// `decryptMedia` decrypts the vector the same way `decryptFile` does;
  /// only its failures differ, by carrying the media hash key.
  func testDecryptMediaVector() throws {
    XCTAssertEqual(
      try decryptMedia(
        key: Self.key,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"),
        encrypted: Self.vectorCiphertext),
      Self.vectorPlaintext)
  }

  // MARK: Round trips and sizes

  /// Round trip at every frame boundary, with `encryptedFileSize` matching
  /// the bytes produced.
  func testRoundTripAndSizes() throws {
    let full = (0..<4096).map { UInt8($0 % 251) }
    for length in [0, 1, 1023, 1024, 1025, 2048, 2049, 3000] {
      let plaintext = Array(full[0..<length])
      let encrypted = try encryptFile(key: Self.key, plaintext: plaintext)
      let expected = try XCTUnwrap(encryptedFileSize(UInt64(length)))
      XCTAssertEqual(UInt64(encrypted.count), expected, "length \(length)")
      XCTAssertEqual(
        try decryptFile(key: Self.key, ciphertext: encrypted), plaintext,
        "length \(length)")
    }
  }

  /// The exact chunk framing the wire format freezes: intermediate chunks
  /// are 1041 bytes, the last frame is 17 bytes plus the remaining tail.
  func testFrameSizes() throws {
    let cases: [(Int, Int)] = [
      (0, 24),
      (1, 24 + 17 + 1),
      (1024, 24 + 1041),
      (1025, 24 + 1041 + 18),
      (2048, 24 + 1041 + 1041),
      (2049, 24 + 1041 + 1041 + 18),
    ]
    for (plaintextLength, expectedSize) in cases {
      let encrypted = try encryptFile(
        key: Self.key, plaintext: [UInt8](repeating: 5, count: plaintextLength))
      XCTAssertEqual(encrypted.count, expectedSize, "plaintext \(plaintextLength)")
    }
  }

  /// `encryptedFileSize` agrees with the framed output at every boundary.
  func testEncryptedFileSize() {
    XCTAssertEqual(encryptedFileSize(0), 24)
    XCTAssertEqual(encryptedFileSize(1), 1 + 24 + 17)
    XCTAssertEqual(encryptedFileSize(1023), 1023 + 24 + 17)
    XCTAssertEqual(encryptedFileSize(1024), 1024 + 24 + 17)
    XCTAssertEqual(encryptedFileSize(1025), 1025 + 24 + 2 * 17)
    XCTAssertEqual(encryptedFileSize(2048), 2048 + 24 + 2 * 17)
    XCTAssertEqual(encryptedFileSize(2049), 2049 + 24 + 3 * 17)
    // The sum cannot be represented as a UInt64.
    XCTAssertNil(encryptedFileSize(UInt64.max))
  }

  /// Empty input produces only the 24-byte header, which decrypts back to
  /// nothing.
  func testEmptyFileIsHeaderOnly() throws {
    let encrypted = try encryptFile(key: Self.key, plaintext: [])
    XCTAssertEqual(encrypted.count, 24)
    XCTAssertEqual(try decryptFile(key: Self.key, ciphertext: encrypted), [])
  }

  /// A chunk equal to the plaintext chunk size is held back for `finish`,
  /// so `push` emits only the header.
  func testPushHoldsBackLastChunk() throws {
    var encryptor = try FileEncryptor(key: Self.key)
    var out = try encryptor.push([UInt8](repeating: 7, count: 1024))
    XCTAssertEqual(out.count, 24)
    out += try encryptor.finish()
    XCTAssertEqual(out.count, 24 + 1041)
  }

  /// Framing depends only on the plaintext, so splitting the input across
  /// arbitrary `push` calls yields the same ciphertext size and opens to
  /// the same plaintext.
  func testOutputSizeIndependentOfSplitPoints() throws {
    let plaintext = (0..<3000).map { UInt8($0 % 251) }
    let oneShot = try encryptFile(key: Self.key, plaintext: plaintext)

    var encryptor = try FileEncryptor(key: Self.key)
    var byteWise: [UInt8] = []
    for byte in plaintext {
      byteWise += try encryptor.push([byte])
    }
    byteWise += try encryptor.finish()

    XCTAssertEqual(oneShot.count, byteWise.count)
    XCTAssertEqual(oneShot.count, 24 + 1041 + 1041 + 969)
    XCTAssertEqual(try decryptFile(key: Self.key, ciphertext: byteWise), plaintext)
  }

  // MARK: Faults

  /// Dropping the final frame is detected as truncation.
  func testMissingFinalFrameRejected() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 493)])
    assertThrows(.truncated) {
      try decryptFile(key: Self.key, ciphertext: truncated)
    }
  }

  /// Cutting inside the final frame fails its MAC, which cannot be told
  /// from tampering, so it is reported as the last frame failing rather
  /// than as a clean truncation.
  func testCutInsideFinalFrameRejected() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 10)])
    assertThrows(.lastFrameAuthenticationFailed) {
      try decryptFile(key: Self.key, ciphertext: truncated)
    }
  }

  /// An input that ends inside the 24-byte header is rejected as
  /// truncated.
  func testHeaderIncompleteRejected() throws {
    for length in [0, 1, 23] {
      var decryptor = try FileDecryptor(key: Self.key)
      _ = try decryptor.push([UInt8](repeating: 0, count: length))
      assertThrows(.truncated, "length \(length)") { try decryptor.finish() }
    }
  }

  /// A full final frame followed by more data is rejected, since a file
  /// whose final frame is not last is malformed.
  func testDataAfterFinalFrameRejected() throws {
    let encrypted = try encryptFile(
      key: Self.key, plaintext: [UInt8](repeating: 9, count: 1024))
    XCTAssertEqual(encrypted.count, 24 + 1041)

    var decryptor = try FileDecryptor(key: Self.key)
    assertThrows(.dataAfterFinalFrame) {
      try decryptor.push(encrypted + [UInt8](repeating: 0, count: 100))
    }
  }

  /// A tampered frame byte fails authentication and yields no plaintext.
  /// The last frame's failure is its own case, since it may also be cut
  /// short.
  func testTamperedFrameRejected() throws {
    let faults: [(index: Int, fault: XChatError.FileFault)] = [
      (24, .authenticationFailed),
      (100, .authenticationFailed),
      (1064, .authenticationFailed),
      (24 + 1041 + 10, .lastFrameAuthenticationFailed),
    ]
    for (index, fault) in faults {
      var tampered = Self.vectorCiphertext
      tampered[index] ^= 0x80
      assertThrows(fault, "byte \(index)") {
        try decryptFile(key: Self.key, ciphertext: tampered)
      }
    }
  }

  /// A tampered header fails the first frame's MAC.
  func testTamperedHeaderRejected() throws {
    var tampered = Self.vectorCiphertext
    tampered[0] ^= 1
    assertThrows(.authenticationFailed) {
      try decryptFile(key: Self.key, ciphertext: tampered)
    }
  }

  // MARK: Media faults carry the media hash key

  private static let mediaHashKey = TestVectors.string("media_conversation_key_hash_key")

  /// A frame that fails with data behind it fails authentication, for that
  /// media.
  func testMediaBadFrameNamesTheMedia() throws {
    var tampered = Self.vectorCiphertext
    tampered[24 + 10] ^= 0x80
    assertThrows(.decryption(.file(.authenticationFailed, mediaHashKey: Self.mediaHashKey))) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: tampered)
    }
  }

  /// A last frame that fails its MAC is its own fault, for that media,
  /// since the bytes may also be cut short inside it.
  func testMediaBadLastFrameNamesTheMedia() throws {
    var tampered = Self.vectorCiphertext
    tampered[24 + 1041 + 10] ^= 0x80
    assertThrows(
      .decryption(.file(.lastFrameAuthenticationFailed, mediaHashKey: Self.mediaHashKey))
    ) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: tampered)
    }
  }

  /// Data after the final frame is reported for that media.
  func testMediaTrailingDataNamesTheMedia() throws {
    let encrypted = try encryptFile(
      key: Self.key, plaintext: [UInt8](repeating: 9, count: 1024))
    assertThrows(.decryption(.file(.dataAfterFinalFrame, mediaHashKey: Self.mediaHashKey))) {
      try decryptMedia(
        key: Self.key,
        mediaHashKey: Self.mediaHashKey,
        encrypted: encrypted + [UInt8](repeating: 0, count: 100))
    }
  }

  /// A missing final frame reports that media's bytes as truncated.
  func testMediaTruncationNamesTheMedia() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 493)])
    assertThrows(.decryption(.file(.truncated, mediaHashKey: Self.mediaHashKey))) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: truncated)
    }
  }

  // MARK: Input and state validation

  /// Keys must be 32 bytes at every entry point.
  func testKeyLengthValidation() {
    for length in [0, 16, 31, 33] {
      let key = [UInt8](repeating: 0, count: length)
      assertThrows(.invalidInput(.conversationKeyLength(length))) {
        _ = try FileEncryptor(key: key)
      }
      assertThrows(.invalidInput(.conversationKeyLength(length))) {
        try FileDecryptor(key: key)
      }
      assertThrows(.invalidInput(.conversationKeyLength(length))) {
        try encryptFile(key: key, plaintext: [1])
      }
      assertThrows(.invalidInput(.conversationKeyLength(length))) {
        try decryptFile(key: key, ciphertext: [1])
      }
    }
  }

  /// `finish` consumes the encryptor; later calls say so.
  func testFinishedEncryptorRejectsReuse() throws {
    var encryptor = try FileEncryptor(key: Self.key)
    _ = try encryptor.finish()
    assertThrows(.invalidInput(.fileEncryptorFinished)) {
      try encryptor.push([1, 2, 3])
    }
    assertThrows(.invalidInput(.fileEncryptorFinished)) {
      try encryptor.finish()
    }
  }

  /// `finish` consumes the decryptor, even when it fails, matching the
  /// reference's move semantics.
  func testFinishedDecryptorRejectsReuse() throws {
    var failed = try FileDecryptor(key: Self.key)
    XCTAssertThrowsError(try failed.finish())
    assertThrows(.invalidInput(.fileDecryptorFinished)) {
      try failed.finish()
    }

    var decryptor = try FileDecryptor(key: Self.key)
    _ = try decryptor.push(Self.vectorCiphertext)
    _ = try decryptor.finish()
    assertThrows(.invalidInput(.fileDecryptorFinished)) {
      try decryptor.push([1])
    }
    assertThrows(.invalidInput(.fileDecryptorFinished)) {
      try decryptor.finish()
    }
  }
}
