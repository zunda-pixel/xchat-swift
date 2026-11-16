import Testing

@testable import XChat

/// How a file decrypts under a key: the frames this SDK does not write
/// (data after a final frame shorter than a full one, push and rekey
/// frames, and the undefined tags secretstream authenticates), which calls
/// name the media whose bytes fail, and a key of the wrong length given
/// with a media hash key.
struct FileDecryptionTests {
  /// The conversation key is itself the secretstream key, so the media
  /// vector decrypts with it directly.
  private static let key = TestVectors.bytes("conversation_key_b64")
  private static let vectorCiphertext = TestVectors.bytes("media_conversation_key_encrypted_b64")
  private static let mediaHashKey = TestVectors.string("media_conversation_key_hash_key")

  /// `fault` for a file under a key the caller holds, which names no media.
  private static func unnamed(_ fault: XChatError.FileFailure) -> XChatError {
    .decryption(.file(fault, mediaHashKey: nil))
  }

  /// Data after a final frame shorter than a full one, or after the header
  /// of an empty file, is read as part of a frame, since frames are read a
  /// full frame at a time: the frame does not authenticate, as the last
  /// frame when the data fits in it, and as a frame with more after it
  /// when the data runs past a full frame. The files are 1 byte and empty.
  @Test(arguments: [([UInt8(9)], 24 + 18), ([], 24)])
  func dataAfterAShortFinalFrameFailsAsAFrame(plaintext: [UInt8], fileSize: Int) throws {
    let encrypted = try encryptFile(key: Self.key, plaintext: plaintext)
    #expect(encrypted.count == fileSize)
    #expect(throws: Self.unnamed(.lastFrameAuthenticationFailed)) {
      try decryptFile(key: Self.key, ciphertext: encrypted + [UInt8](repeating: 0, count: 10))
    }
    #expect(throws: Self.unnamed(.authenticationFailed)) {
      try decryptFile(key: Self.key, ciphertext: encrypted + [UInt8](repeating: 0, count: 1100))
    }
  }

  /// A frame that authenticates under the key but carries a tag
  /// secretstream does not define, which only a sender holding the key can
  /// write, is reported as that tag, whether more of the file follows it
  /// or it is the last frame.
  @Test func undefinedFrameTagIsRefused() throws {
    let (header, pusher) = try SecretStreamPush.start(key: Self.key)
    var push = pusher
    let middle = try push.push([UInt8](repeating: 1, count: 1024), rawTag: 0x10)
    let last = try push.push([2], tag: .final)

    #expect(throws: Self.unnamed(.unknownTag(0x10)), "followed by the final frame") {
      try XChatCore().decryptFileWithKey(header + middle + last, key: Self.key)
    }
    #expect(throws: Self.unnamed(.unknownTag(0x10)), "as the last frame") {
      try XChatCore().decryptFileWithKey(header + middle, key: Self.key)
    }
  }

  /// Push and rekey frames, which secretstream defines, decrypt as the
  /// file's other frames: only the tags it does not define are refused.
  @Test func pushAndRekeyFramesDecrypt() throws {
    let (header, pusher) = try SecretStreamPush.start(key: Self.key)
    var push = pusher
    let first = [UInt8](repeating: 1, count: 1024)
    let second = [UInt8](repeating: 2, count: 1024)
    let pushFrame = try push.push(first, tag: .push)
    let rekeyFrame = try push.push(second, tag: .rekey)
    let last = try push.push([3], tag: .final)

    #expect(
      try XChatCore().decryptFileWithKey(header + pushFrame + rekeyFrame + last, key: Self.key)
        == first + second + [3])
  }

  /// The same bytes under the same key name the media from the calls given
  /// its media hash key, and from no other: the conversation key that opens
  /// the v0 message's media also opens it as a key the caller holds.
  @Test func callDecidesWhetherTheMediaIsNamed() throws {
    let core = XChatCore()
    let truncated = Array(Self.vectorCiphertext[0..<(Self.vectorCiphertext.count - 493)])
    let event = TestVectors.string("event_conversation_key_media_b64")
    let keys = [TestVectors.string("event_conversation_key_version"): Self.key]
    func pushAll(_ decryptor: FileDecryptor) throws -> [UInt8] {
      var decryptor = decryptor
      return try decryptor.push(truncated) + decryptor.finish()
    }

    let named = XChatError.decryption(.file(.truncated, mediaHashKey: Self.mediaHashKey))
    #expect(throws: named, "decryptFile") {
      try core.decryptFile(
        truncated, eventB64: event, conversationKeys: keys, mediaHashKey: Self.mediaHashKey)
    }
    #expect(throws: named, "fileDecryptor") {
      try pushAll(
        core.fileDecryptor(
          eventB64: event, conversationKeys: keys, mediaHashKey: Self.mediaHashKey))
    }
    #expect(throws: named, "FileDecryptor(key:mediaHashKey:)") {
      try pushAll(FileDecryptor(key: Self.key, mediaHashKey: Self.mediaHashKey))
    }
    #expect(throws: Self.unnamed(.truncated), "decryptFileWithKey") {
      try core.decryptFileWithKey(truncated, key: Self.key)
    }
    #expect(throws: Self.unnamed(.truncated), "FileDecryptor(key:)") {
      try pushAll(FileDecryptor(key: Self.key))
    }
  }

  /// A key of the wrong length given with a media hash key is reported as
  /// the file's key, as `FileDecryptor(key:)` and the other entry points
  /// report it: the key is the caller's, whichever media it is for.
  @Test(arguments: [0, 16, 31, 33])
  func aKeyOfTheWrongLengthIsTheFilesKeyWithAMediaHashKeyToo(length: Int) {
    #expect(throws: XChatError.invalidInput(.fileKeyLength(length))) {
      try FileDecryptor(key: [UInt8](repeating: 0, count: length), mediaHashKey: "h")
    }
  }
}
