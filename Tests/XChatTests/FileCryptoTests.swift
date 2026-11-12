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

  /// Asserts the closure throws an `XChatError` with the given kind and
  /// exact message.
  private func assertThrows<T>(
    _ expectedMessage: String,
    kind: ErrorKind = .decryption,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
      let error = error as? XChatError
      XCTAssertEqual(error?.kind, kind, file: file, line: line)
      XCTAssertEqual(error?.message, expectedMessage, file: file, line: line)
    }
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

  /// `decryptMedia` names the media in failures and decrypts the vector
  /// the same way `decryptFile` does.
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
    assertThrows("stream truncated: ended before final frame") {
      try decryptFile(key: Self.key, ciphertext: truncated)
    }
  }

  /// Cutting inside the final frame fails its MAC, which is reported as a
  /// pull failure rather than a clean truncation.
  func testCutInsideFinalFrameRejected() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 10)])
    assertThrows("secretstream pull failed") {
      try decryptFile(key: Self.key, ciphertext: truncated)
    }
  }

  /// An input that ends inside the 24-byte header is rejected as a
  /// truncated header.
  func testHeaderIncompleteRejected() throws {
    for length in [0, 1, 23] {
      var decryptor = try FileDecryptor(key: Self.key)
      _ = try decryptor.push([UInt8](repeating: 0, count: length))
      XCTAssertThrowsError(try decryptor.finish()) { error in
        XCTAssertEqual(
          (error as? XChatError)?.message,
          "stream ended before header was complete",
          "length \(length)")
      }
    }
  }

  /// A full final frame followed by more data is rejected, since a file
  /// whose final frame is not last is malformed.
  func testDataAfterFinalFrameRejected() throws {
    let encrypted = try encryptFile(
      key: Self.key, plaintext: [UInt8](repeating: 9, count: 1024))
    XCTAssertEqual(encrypted.count, 24 + 1041)

    var decryptor = try FileDecryptor(key: Self.key)
    assertThrows("data after final stream frame") {
      try decryptor.push(encrypted + [UInt8](repeating: 0, count: 100))
    }
  }

  /// A tampered frame byte fails authentication and yields no plaintext.
  func testTamperedFrameRejected() throws {
    for index in [24, 100, 1064, 24 + 1041 + 10] {
      var tampered = Self.vectorCiphertext
      tampered[index] ^= 0x80
      assertThrows("secretstream pull failed") {
        try decryptFile(key: Self.key, ciphertext: tampered)
      }
    }
  }

  /// A tampered header fails the first frame's MAC.
  func testTamperedHeaderRejected() throws {
    var tampered = Self.vectorCiphertext
    tampered[0] ^= 1
    assertThrows("secretstream pull failed") {
      try decryptFile(key: Self.key, ciphertext: tampered)
    }
  }

  // MARK: Media faults name the media hash key

  private static let mediaHashKey = TestVectors.string("media_conversation_key_hash_key")

  /// A frame that fails with data behind it names the media.
  func testMediaBadFrameNamesTheMedia() throws {
    var tampered = Self.vectorCiphertext
    tampered[24 + 10] ^= 0x80
    assertThrows(
      "the bytes are not the encrypted file of media_hash_key '\(Self.mediaHashKey)', or "
        + "they are corrupted: pass the bytes downloaded for that media hash key"
    ) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: tampered)
    }
  }

  /// A last frame that fails its MAC names the media and lists the causes.
  func testMediaBadLastFrameNamesTheMedia() throws {
    var tampered = Self.vectorCiphertext
    tampered[24 + 1041 + 10] ^= 0x80
    assertThrows(
      "the bytes are not the complete encrypted file of media_hash_key '\(Self.mediaHashKey)': "
        + "they are truncated, corrupted, or another file; pass the complete bytes "
        + "downloaded for that media hash key"
    ) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: tampered)
    }
  }

  /// Data after the final frame names the media and says to pass only its
  /// bytes.
  func testMediaTrailingDataNamesTheMedia() throws {
    let encrypted = try encryptFile(
      key: Self.key, plaintext: [UInt8](repeating: 9, count: 1024))
    assertThrows(
      "the bytes continue past the end of the encrypted file of media_hash_key "
        + "'\(Self.mediaHashKey)': pass only the bytes downloaded for that media hash key"
    ) {
      try decryptMedia(
        key: Self.key,
        mediaHashKey: Self.mediaHashKey,
        encrypted: encrypted + [UInt8](repeating: 0, count: 100))
    }
  }

  /// A missing final frame names the media and says the bytes are
  /// truncated.
  func testMediaTruncationNamesTheMedia() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 493)])
    assertThrows(
      "the bytes of media_hash_key '\(Self.mediaHashKey)' are truncated: pass the complete "
        + "bytes downloaded for that media hash key"
    ) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: truncated)
    }
  }

  // MARK: Input and state validation

  /// Keys must be 32 bytes at every entry point.
  func testKeyLengthValidation() {
    for length in [0, 16, 31, 33] {
      let key = [UInt8](repeating: 0, count: length)
      assertThrows(
        "Conversation key must be 32 bytes", kind: .invalidInput
      ) {
        _ = try FileEncryptor(key: key)
      }
      assertThrows(
        "Conversation key must be 32 bytes", kind: .invalidInput
      ) {
        try FileDecryptor(key: key)
      }
      assertThrows(
        "Conversation key must be 32 bytes", kind: .invalidInput
      ) {
        try encryptFile(key: key, plaintext: [1])
      }
      assertThrows(
        "Conversation key must be 32 bytes", kind: .invalidInput
      ) {
        try decryptFile(key: key, ciphertext: [1])
      }
    }
  }

  /// `finish` consumes the encryptor; later calls say so.
  func testFinishedEncryptorRejectsReuse() throws {
    var encryptor = try FileEncryptor(key: Self.key)
    _ = try encryptor.finish()
    assertThrows("File encryptor already finished", kind: .invalidInput) {
      try encryptor.push([1, 2, 3])
    }
    assertThrows("File encryptor already finished", kind: .invalidInput) {
      try encryptor.finish()
    }
  }

  /// `finish` consumes the decryptor, even when it fails, matching the
  /// reference's move semantics.
  func testFinishedDecryptorRejectsReuse() throws {
    var failed = try FileDecryptor(key: Self.key)
    XCTAssertThrowsError(try failed.finish())
    assertThrows("File decryptor already finished", kind: .invalidInput) {
      try failed.finish()
    }

    var decryptor = try FileDecryptor(key: Self.key)
    _ = try decryptor.push(Self.vectorCiphertext)
    _ = try decryptor.finish()
    assertThrows("File decryptor already finished", kind: .invalidInput) {
      try decryptor.push([1])
    }
    assertThrows("File decryptor already finished", kind: .invalidInput) {
      try decryptor.finish()
    }
  }
}
