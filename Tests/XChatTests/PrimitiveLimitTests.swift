import Testing

@testable import XChat

/// Limits of the primitives the message and file formats are built on:
/// the longest output HKDF derives, and a secretstream frame tag that
/// libsodium authenticates but secretstream does not define.
struct PrimitiveLimitTests {
  /// HKDF-SHA256 derives up to the spec's 255 blocks of 32 bytes.
  @Test func hkdfDerivesUpToTheSpecMaximum() {
    #expect(hkdf(secret: [1], salt: "s", length: 8160).count == 8160)
  }

  /// libsodium authenticates any tag byte a sender writes; a frame whose tag
  /// secretstream does not define is refused without advancing the stream.
  @Test func undefinedSecretStreamTagIsRefused() throws {
    let key = TestVectors.bytes("conversation_key_b64")
    let (header, pusher) = try SecretStreamPush.start(key: key)
    var push = pusher
    let frame = try push.push([1, 2, 3], rawTag: 0x10)

    var pull = try SecretStreamPull(header: header, key: key)
    #expect(throws: PrimitiveError.unknownStreamTag(0x10)) { try pull.pull(frame) }
  }
}
