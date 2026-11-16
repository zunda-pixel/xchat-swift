import Testing

@testable import XChat

/// A plaintext length and the framed file size `encryptFile` produces.
struct FileFrameCase: Sendable {
  var plaintextLength: Int
  var expectedSize: Int
}

private let fileFrameCases: [FileFrameCase] = [
  FileFrameCase(plaintextLength: 0, expectedSize: 24),
  FileFrameCase(plaintextLength: 1, expectedSize: 24 + 17 + 1),
  FileFrameCase(plaintextLength: 1024, expectedSize: 24 + 1041),
  FileFrameCase(plaintextLength: 1025, expectedSize: 24 + 1041 + 18),
  FileFrameCase(plaintextLength: 2048, expectedSize: 24 + 1041 + 1041),
  FileFrameCase(plaintextLength: 2049, expectedSize: 24 + 1041 + 1041 + 18),
]

/// A byte offset and the fault tampering it produces.
struct FileTamperCase: Sendable {
  var index: Int
  var fault: XChatError.FileFailure
}

private let fileTamperCases: [FileTamperCase] = [
  FileTamperCase(index: 24, fault: .authenticationFailed),
  FileTamperCase(index: 100, fault: .authenticationFailed),
  FileTamperCase(index: 1064, fault: .authenticationFailed),
  FileTamperCase(index: 24 + 1041 + 10, fault: .lastFrameAuthenticationFailed),
]

/// The file wire format — `header (24B) || chunks` — through
/// `FileEncryptor`/`FileDecryptor`, including the core's cross-binding
/// media vector, framing rules, and every truncation and tampering fault.
struct FileCryptoTests {
  /// The conversation key is itself the secretstream key, so the media
  /// vector decrypts with it directly.
  private static let key = TestVectors.bytes("conversation_key_b64")
  private static let vectorCiphertext = TestVectors.bytes("media_conversation_key_encrypted_b64")
  private static let vectorPlaintext = TestVectors.bytes("media_conversation_key_plaintext_b64")

  /// Asserts the closure throws `expected`.
  private func assertThrows<T>(
    _ expected: XChatError,
    _ comment: Comment? = nil,
    _ body: () throws -> T
  ) {
    #expect(throws: expected, comment) { try body() }
  }

  /// Asserts the closure throws `fault` for a file under a key the caller
  /// holds.
  private func assertThrows<T>(
    _ fault: XChatError.FileFailure,
    _ comment: Comment? = nil,
    _ body: () throws -> T
  ) {
    assertThrows(
      .decryption(.file(fault, mediaHashKey: nil)), comment, body)
  }

  // MARK: Cross-binding vector

  /// The core's media ciphertext decrypts through the file layer whether
  /// fed whole, one byte at a time, or in 700-byte pieces.
  @Test func vectorDecryptsThroughFileDecryptor() throws {
    #expect(Self.vectorCiphertext.count == 1558)
    #expect(Self.vectorPlaintext.count == 1500)

    #expect(
      try decryptFile(key: Self.key, ciphertext: Self.vectorCiphertext)
        == Self.vectorPlaintext)

    var byteWise = try FileDecryptor(key: Self.key)
    var byteWisePlaintext: [UInt8] = []
    for byte in Self.vectorCiphertext {
      byteWisePlaintext += try byteWise.push([byte])
    }
    byteWisePlaintext += try byteWise.finish()
    #expect(byteWisePlaintext == Self.vectorPlaintext)

    var chunked = try FileDecryptor(key: Self.key)
    var chunkedPlaintext: [UInt8] = []
    var offset = 0
    while offset < Self.vectorCiphertext.count {
      let end = min(offset + 700, Self.vectorCiphertext.count)
      chunkedPlaintext += try chunked.push(Array(Self.vectorCiphertext[offset..<end]))
      offset = end
    }
    chunkedPlaintext += try chunked.finish()
    #expect(chunkedPlaintext == Self.vectorPlaintext)
  }

  /// `decryptMedia` decrypts the vector the same way `decryptFile` does;
  /// only its failures differ, by carrying the media hash key.
  @Test func decryptMediaVector() throws {
    #expect(
      try decryptMedia(
        key: Self.key,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"),
        encrypted: Self.vectorCiphertext)
        == Self.vectorPlaintext)
  }

  // MARK: Round trips and sizes

  /// Round trip at every frame boundary, with `encryptedFileSize` matching
  /// the bytes produced.
  @Test(arguments: [0, 1, 1023, 1024, 1025, 2048, 2049, 3000])
  func roundTripAndSizes(length: Int) throws {
    let full = (0..<4096).map { UInt8($0 % 251) }
    let plaintext = Array(full[0..<length])
    let encrypted = try encryptFile(key: Self.key, plaintext: plaintext)
    let expected = try #require(encryptedFileSize(UInt64(length)))
    #expect(UInt64(encrypted.count) == expected, "length \(length)")
    #expect(
      try decryptFile(key: Self.key, ciphertext: encrypted) == plaintext,
      "length \(length)")
  }

  /// The exact chunk framing the wire format freezes: intermediate chunks
  /// are 1041 bytes, the last frame is 17 bytes plus the remaining tail.
  @Test(arguments: fileFrameCases)
  func frameSizes(testCase: FileFrameCase) throws {
    let encrypted = try encryptFile(
      key: Self.key,
      plaintext: [UInt8](repeating: 5, count: testCase.plaintextLength))
    #expect(
      encrypted.count == testCase.expectedSize,
      "plaintext \(testCase.plaintextLength)")
  }

  /// `encryptedFileSize` agrees with the framed output at every boundary.
  @Test func encryptedFileSizeMatchesFrames() {
    #expect(encryptedFileSize(0) == 24)
    #expect(encryptedFileSize(1) == 1 + 24 + 17)
    #expect(encryptedFileSize(1023) == 1023 + 24 + 17)
    #expect(encryptedFileSize(1024) == 1024 + 24 + 17)
    #expect(encryptedFileSize(1025) == 1025 + 24 + 2 * 17)
    #expect(encryptedFileSize(2048) == 2048 + 24 + 2 * 17)
    #expect(encryptedFileSize(2049) == 2049 + 24 + 3 * 17)
    // The sum cannot be represented as a UInt64.
    #expect(encryptedFileSize(UInt64.max) == nil)
  }

  /// Empty input produces only the 24-byte header, which decrypts back to
  /// nothing.
  @Test func emptyFileIsHeaderOnly() throws {
    let encrypted = try encryptFile(key: Self.key, plaintext: [])
    #expect(encrypted.count == 24)
    #expect(try decryptFile(key: Self.key, ciphertext: encrypted) == [])
  }

  /// A chunk equal to the plaintext chunk size is held back for `finish`,
  /// so `push` emits only the header.
  @Test func pushHoldsBackLastChunk() throws {
    var encryptor = try FileEncryptor(key: Self.key)
    var out = try encryptor.push([UInt8](repeating: 7, count: 1024))
    #expect(out.count == 24)
    out += try encryptor.finish()
    #expect(out.count == 24 + 1041)
  }

  /// Framing depends only on the plaintext, so splitting the input across
  /// arbitrary `push` calls yields the same ciphertext size and opens to
  /// the same plaintext.
  @Test func outputSizeIndependentOfSplitPoints() throws {
    let plaintext = (0..<3000).map { UInt8($0 % 251) }
    let oneShot = try encryptFile(key: Self.key, plaintext: plaintext)

    var encryptor = try FileEncryptor(key: Self.key)
    var byteWise: [UInt8] = []
    for byte in plaintext {
      byteWise += try encryptor.push([byte])
    }
    byteWise += try encryptor.finish()

    #expect(oneShot.count == byteWise.count)
    #expect(oneShot.count == 24 + 1041 + 1041 + 969)
    #expect(try decryptFile(key: Self.key, ciphertext: byteWise) == plaintext)
  }

  // MARK: Faults

  /// Dropping the final frame is detected as truncation.
  @Test func missingFinalFrameRejected() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 493)])
    assertThrows(.truncated) {
      try decryptFile(key: Self.key, ciphertext: truncated)
    }
  }

  /// Cutting inside the final frame fails its MAC, which cannot be told
  /// from tampering, so it is reported as the last frame failing rather
  /// than as a clean truncation.
  @Test func cutInsideFinalFrameRejected() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 10)])
    assertThrows(.lastFrameAuthenticationFailed) {
      try decryptFile(key: Self.key, ciphertext: truncated)
    }
  }

  /// An input that ends inside the 24-byte header is rejected as
  /// truncated.
  @Test(arguments: [0, 1, 23])
  func headerIncompleteRejected(length: Int) throws {
    var decryptor = try FileDecryptor(key: Self.key)
    _ = try decryptor.push([UInt8](repeating: 0, count: length))
    assertThrows(.truncated, "length \(length)") { try decryptor.finish() }
  }

  /// A full final frame followed by more data is rejected, since a file
  /// whose final frame is not last is malformed.
  @Test func dataAfterFinalFrameRejected() throws {
    let encrypted = try encryptFile(
      key: Self.key, plaintext: [UInt8](repeating: 9, count: 1024))
    #expect(encrypted.count == 24 + 1041)

    var decryptor = try FileDecryptor(key: Self.key)
    assertThrows(.dataAfterFinalFrame) {
      try decryptor.push(encrypted + [UInt8](repeating: 0, count: 100))
    }
  }

  /// A tampered frame byte fails authentication and yields no plaintext.
  /// The last frame's failure is its own case, since it may also be cut
  /// short.
  @Test(arguments: fileTamperCases)
  func tamperedFrameRejected(testCase: FileTamperCase) throws {
    var tampered = Self.vectorCiphertext
    tampered[testCase.index] ^= 0x80
    assertThrows(testCase.fault, "byte \(testCase.index)") {
      try decryptFile(key: Self.key, ciphertext: tampered)
    }
  }

  /// A tampered header fails the first frame's MAC.
  @Test func tamperedHeaderRejected() throws {
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
  @Test func mediaBadFrameNamesTheMedia() throws {
    var tampered = Self.vectorCiphertext
    tampered[24 + 10] ^= 0x80
    assertThrows(.decryption(.file(.authenticationFailed, mediaHashKey: Self.mediaHashKey))) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: tampered)
    }
  }

  /// A last frame that fails its MAC is its own fault, for that media,
  /// since the bytes may also be cut short inside it.
  @Test func mediaBadLastFrameNamesTheMedia() throws {
    var tampered = Self.vectorCiphertext
    tampered[24 + 1041 + 10] ^= 0x80
    assertThrows(
      .decryption(.file(.lastFrameAuthenticationFailed, mediaHashKey: Self.mediaHashKey))
    ) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: tampered)
    }
  }

  /// Data after the final frame is reported for that media.
  @Test func mediaTrailingDataNamesTheMedia() throws {
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
  @Test func mediaTruncationNamesTheMedia() throws {
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 493)])
    assertThrows(.decryption(.file(.truncated, mediaHashKey: Self.mediaHashKey))) {
      try decryptMedia(key: Self.key, mediaHashKey: Self.mediaHashKey, encrypted: truncated)
    }
  }

  // MARK: Input and state validation

  /// Keys must be 32 bytes at every entry point, and a key of another
  /// length is reported as the file's key, as `encryptFileWithKey` and
  /// `decryptFileWithKey` report it.
  @Test(arguments: [0, 16, 31, 33])
  func keyLengthValidation(length: Int) {
    let key = [UInt8](repeating: 0, count: length)
    assertThrows(.invalidInput(.fileKeyLength(length))) {
      _ = try FileEncryptor(key: key)
    }
    assertThrows(.invalidInput(.fileKeyLength(length))) {
      try FileDecryptor(key: key)
    }
    assertThrows(.invalidInput(.fileKeyLength(length))) {
      try encryptFile(key: key, plaintext: [1])
    }
    assertThrows(.invalidInput(.fileKeyLength(length))) {
      try decryptFile(key: key, ciphertext: [1])
    }
  }

  /// `finish` consumes the encryptor; later calls say so.
  @Test func finishedEncryptorRejectsReuse() throws {
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
  @Test func finishedDecryptorRejectsReuse() throws {
    var failed = try FileDecryptor(key: Self.key)
    #expect(throws: (any Error).self) { try failed.finish() }
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
