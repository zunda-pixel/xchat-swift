import Testing

@testable import XChat

/// `crypto_secretstream_xchacha20poly1305` against the core's cross-binding
/// media vector, plus round trips, rekeying and authentication failures.
struct SecretStreamTests {
  /// The core's media vector: the conversation key is the raw secretstream
  /// key, so this validates header derivation, frame encryption, MACs and
  /// nonce chaining against ciphertext the Rust core produced.
  private static let key = TestVectors.bytes("conversation_key_b64")
  private static let encrypted = TestVectors.bytes("media_conversation_key_encrypted_b64")
  private static let plaintext = TestVectors.bytes("media_conversation_key_plaintext_b64")

  /// Guards the fixture's shape: a 24-byte header, one full 1041-byte
  /// frame, and a 493-byte final frame for 476 plaintext bytes.
  @Test func vectorShape() {
    #expect(Self.key.count == 32)
    #expect(Self.plaintext.count == 1500)
    #expect(Self.encrypted.count == 24 + 1041 + 493)
  }

  /// Pulls the vector frame by frame: the first frame is a message and the
  /// last is final.
  @Test func vectorOpensFrameByFrame() throws {
    var pull = try SecretStreamPull(header: Array(Self.encrypted[0..<24]), key: Self.key)
    var plaintext: [UInt8] = []
    var tags: [SecretStreamTag] = []
    var offset = 24
    while offset < Self.encrypted.count {
      let end = min(offset + 1041, Self.encrypted.count)
      let (message, tag) = try pull.pull(Array(Self.encrypted[offset..<end]))
      plaintext += message
      tags.append(tag)
      offset = end
    }
    #expect(plaintext == Self.plaintext)
    #expect(tags == [.message, .final])
  }

  /// Round trip at every frame boundary and a partial tail.
  @Test(arguments: [0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024, 1025, 2048, 2049])
  func roundTripAllLengths(length: Int) throws {
    let key = (0..<32).map { UInt8(($0 * 7) % 251) }
    let full = (0..<5000).map { UInt8($0 % 251) }

    let message = Array(full[0..<length])
    let (header, pusher) = try SecretStreamPush.start(key: key)
    var push = pusher
    let frame = try push.push(message, tag: .final)
    #expect(frame.count == 17 + length, "length \(length)")

    var pull = try SecretStreamPull(header: header, key: key)
    let (decrypted, tag) = try pull.pull(frame)
    #expect(decrypted == message, "length \(length)")
    #expect(tag == .final)
  }

  /// A frame with an empty message still carries the tag and its MAC.
  @Test func emptyMessage() throws {
    let key = TestVectors.bytes("conversation_key_b64")
    let (header, pusher) = try SecretStreamPush.start(key: key)
    var push = pusher
    let frame = try push.push([], tag: .message)
    #expect(frame.count == 17)

    var pull = try SecretStreamPull(header: header, key: key)
    let (decrypted, tag) = try pull.pull(frame)
    #expect(decrypted == [])
    #expect(tag == .message)
  }

  /// Every tag in sequence, including `rekey`, which rotates the key and
  /// nonce on both sides between frames.
  @Test func everyTagInSequence() throws {
    let key = TestVectors.bytes("conversation_key_b64")
    let messages: [(SecretStreamTag, [UInt8])] = [
      (.message, Array("first".utf8)),
      (.push, Array("second".utf8)),
      (.rekey, Array("third".utf8)),
      (.message, Array("fourth".utf8)),
      (.rekey, Array("fifth".utf8)),
      (.push, Array("sixth".utf8)),
      (.final, Array("seventh".utf8)),
    ]
    let (header, pusher) = try SecretStreamPush.start(key: key)
    var push = pusher
    var frames: [[UInt8]] = []
    for (tag, message) in messages {
      frames.append(try push.push(message, tag: tag))
    }

    var pull = try SecretStreamPull(header: header, key: key)
    for (index, (expectedTag, expectedMessage)) in messages.enumerated() {
      let (message, tag) = try pull.pull(frames[index])
      #expect(tag == expectedTag, "frame \(index)")
      #expect(message == expectedMessage, "frame \(index)")
    }
  }

  /// Associated data is authenticated against the frame, as the reference
  /// test suite's "personal privacy is paramount" example.
  @Test func associatedDataRoundTrip() throws {
    let key = TestVectors.bytes("conversation_key_b64")
    let aad = Array("beware of giving it away".utf8)
    let message = Array("personal privacy is paramount".utf8)

    let (header, pusher) = try SecretStreamPush.start(key: key)
    var push = pusher
    let frame = try push.push(message, associatedData: aad, tag: .final)

    var pull = try SecretStreamPull(header: header, key: key)
    let (decrypted, _) = try pull.pull(frame, associatedData: aad)
    #expect(decrypted == message)
  }

  /// The same frame under different associated data must fail
  /// verification and yield no plaintext.
  @Test func associatedDataMismatchRejected() throws {
    let key = TestVectors.bytes("conversation_key_b64")
    let (header, pusher) = try SecretStreamPush.start(key: key)
    var push = pusher
    let frame = try push.push([1, 2, 3], associatedData: Array("right".utf8), tag: .final)

    var pull = try SecretStreamPull(header: header, key: key)
    #expect(throws: PrimitiveError.authenticationFailed) {
      try pull.pull(frame, associatedData: Array("wrong".utf8))
    }
  }

  /// A header byte changes the derived subkey and nonce, so the first frame
  /// no longer authenticates.
  @Test func tamperedHeaderRejected() throws {
    let key = TestVectors.bytes("conversation_key_b64")
    #expect(Self.encrypted.count == 1558)

    var header = Array(Self.encrypted[0..<24])
    header[0] ^= 1
    var pull = try SecretStreamPull(header: header, key: key)
    #expect(throws: (any Error).self) {
      try pull.pull(Array(Self.encrypted[24..<1065]))
    }

    // The wrong key fails the same way.
    var wrongKey = key
    wrongKey[31] ^= 1
    var wrongKeyPull = try SecretStreamPull(header: Array(Self.encrypted[0..<24]), key: wrongKey)
    #expect(throws: (any Error).self) {
      try wrongKeyPull.pull(Array(Self.encrypted[24..<1065]))
    }
  }

  /// Tampering anywhere in the first frame — tag byte, ciphertext body, or
  /// MAC — is caught before any plaintext is produced.
  @Test(arguments: [24, 25, 100, 1064])
  func tamperedFrameRejected(index: Int) throws {
    let key = TestVectors.bytes("conversation_key_b64")
    var tampered = Self.encrypted
    tampered[index] ^= 0x80
    var framePull = try SecretStreamPull(header: Array(tampered[0..<24]), key: key)
    #expect(throws: (any Error).self) {
      try framePull.pull(Array(tampered[24..<1065]))
    }
  }

  /// A frame shorter than the 17-byte overhead is rejected before any MAC
  /// work, and the stream is not advanced.
  @Test(arguments: [0, 1, 16])
  func shortFrameRejected(length: Int) throws {
    let key = TestVectors.bytes("conversation_key_b64")
    let header = Array(Self.encrypted[0..<24])
    var pull = try SecretStreamPull(header: header, key: key)
    #expect(throws: PrimitiveError.ciphertextTooShort) {
      try pull.pull([UInt8](repeating: 0, count: length))
    }
  }
}
