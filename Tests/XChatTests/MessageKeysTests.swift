import XCTest

@testable import XChat

/// Per-message, per-attachment and media-message-id derivation against the
/// reference implementation's known answers.
final class MessageKeysTests: XCTestCase {
  private static func hex(_ string: String) -> [UInt8] {
    try! Hex.decode(string)
  }

  /// The reference's `message_and_attachment_keys_match_known_answers`.
  func testMessageAndAttachmentKeysMatchKnownAnswers() throws {
    let conversationKey = Self.hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let messageId = "9d8c7b6a-5f4e-4d3c-8b2a-190807060504"

    let messageKey = try deriveMessageKey(
      conversationKey: conversationKey,
      senderId: "1876543210987654321",
      messageId: messageId)
    XCTAssertEqual(
      Hex.encode(messageKey),
      "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084")

    let firstAttachment = try deriveAttachmentKey(
      messageKey: messageKey, attachmentId: messageId)
    XCTAssertEqual(
      Hex.encode(firstAttachment),
      "1ef86545f91f8a3078e276949f7555df2ca584e9c6509b261a558a2e618a1b4b")

    let secondAttachment = try deriveAttachmentKey(
      messageKey: messageKey, attachmentId: "\(messageId)#1")
    XCTAssertEqual(
      Hex.encode(secondAttachment),
      "8a7bc01f2ff35c661140da68606b2370cecc13810f245d791aeb8ba6b40d4ea8")
  }

  /// The reference's `short_sender_id_is_its_digits`.
  func testShortSenderIdIsItsDigits() throws {
    let conversationKey = Self.hex(
      "c3a1f0e2d4b6987a5c3e1f0d2b4a6987c3a1f0e2d4b6987a5c3e1f0d2b4a6987")
    let messageId = "00000000-0000-4000-8000-000000000001"

    let messageKey = try deriveMessageKey(
      conversationKey: conversationKey, senderId: "12", messageId: messageId)
    XCTAssertEqual(
      Hex.encode(messageKey),
      "685bd4a20c7efb64c99147ab5854560c72eac9a826b04880b64e1951d4ef4cc7")

    let attachmentKey = try deriveAttachmentKey(
      messageKey: messageKey, attachmentId: messageId)
    XCTAssertEqual(
      Hex.encode(attachmentKey),
      "4f7d8ca1ef7cb1319743204496358333126086d0a23bdae26bbe5186ba8de093")
  }

  /// The reference's `attachment_key_for_message_id_matches_known_answer`.
  func testAttachmentKeyForMessageIdMatchesKnownAnswer() throws {
    let conversationKey = [UInt8](repeating: 7, count: 32)
    let messageKey = try deriveMessageKey(
      conversationKey: conversationKey,
      senderId: "42",
      messageId: "1975816253410000000")
    let attachmentKey = try deriveAttachmentKey(
      messageKey: messageKey, attachmentId: "1975816253410000000")
    XCTAssertEqual(
      Hex.encode(attachmentKey),
      "d3f7222df89d36796148c1e5a7520b7e71baacde799acf247eeea2c80d0933bf")
  }

  /// A signed or zero-padded sender id derives the same key as its
  /// canonical decimal form.
  func testSenderIdIsCanonicalized() throws {
    let conversationKey = [UInt8](repeating: 1, count: 32)
    let canonical = try deriveMessageKey(
      conversationKey: conversationKey, senderId: "12", messageId: "m")
    let padded = try deriveMessageKey(
      conversationKey: conversationKey, senderId: "+012", messageId: "m")
    XCTAssertEqual(canonical, padded)
  }

  func testNonNumericSenderHasNoMessageKey() {
    XCTAssertThrowsError(
      try deriveMessageKey(
        conversationKey: [UInt8](repeating: 1, count: 32),
        senderId: "sender-1",
        messageId: "m")
    ) { error in
      let error = error as? XChatError
      XCTAssertEqual(error?.kind, .decryption)
      XCTAssertEqual(
        error?.message, "message key needs a numeric sender id, got 'sender-1'")
    }
  }

  func testVersionOneOrMoreUsesAMessageKey() {
    XCTAssertFalse(usesMessageKey(nil))
    XCTAssertFalse(usesMessageKey(0))
    XCTAssertFalse(usesMessageKey(-1))
    XCTAssertTrue(usesMessageKey(1))
    XCTAssertTrue(usesMessageKey(2))
  }

  func testAttachmentIdsFallBackToTheMessageIdByPosition() {
    XCTAssertEqual(resolveAttachmentId(storedId: nil, messageId: "m", index: 0), "m")
    XCTAssertEqual(resolveAttachmentId(storedId: nil, messageId: "m", index: 1), "m#1")
    XCTAssertEqual(resolveAttachmentId(storedId: nil, messageId: "m", index: 2), "m#2")
    XCTAssertEqual(resolveAttachmentId(storedId: "att-9", messageId: "m", index: 0), "att-9")
    XCTAssertEqual(resolveAttachmentId(storedId: "att-9", messageId: "m", index: 3), "att-9")
    // A set empty id counts and wins.
    XCTAssertEqual(resolveAttachmentId(storedId: "", messageId: "m", index: 1), "")
  }

  /// The reference's `media_message_id_matches_known_answer`.
  func testMediaMessageIdMatchesKnownAnswer() {
    let conversationKey = Self.hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    XCTAssertEqual(
      try! deriveMediaMessageId(
        conversationKey: conversationKey,
        conversationKeyVersion: "7",
        senderId: "1001",
        conversationId: "1001:1002",
        mediaHashKeys: ["hash-a", "hash-b"]),
      "906c3ace-dc0c-486c-b242-e0ae974b3c10")
  }

  /// The id is a lowercase v4 UUID and changes with every input.
  func testMediaMessageIdIsAVersion4Uuid() throws {
    let conversationKey = [UInt8](repeating: 3, count: 32)
    let id = try deriveMediaMessageId(
      conversationKey: conversationKey,
      conversationKeyVersion: "7",
      senderId: "1001",
      conversationId: "1001:1002",
      mediaHashKeys: ["hash-a"])
    XCTAssertEqual(id.count, 36)
    XCTAssertEqual(Array(id)[8], Character("-"))
    XCTAssertEqual(Array(id)[13], Character("-"))
    XCTAssertEqual(Array(id)[14], Character("4"))
    XCTAssertEqual(Array(id)[18], Character("-"))
    XCTAssertEqual(Array(id)[23], Character("-"))
    XCTAssertEqual(id, id.lowercased())

    let base = try deriveMediaMessageId(
      conversationKey: conversationKey,
      conversationKeyVersion: "7",
      senderId: "1001",
      conversationId: "1001:1002",
      mediaHashKeys: ["a", "b"])
    let variants = [
      try deriveMediaMessageId(
        conversationKey: [UInt8](repeating: 4, count: 32),
        conversationKeyVersion: "7", senderId: "1001",
        conversationId: "1001:1002", mediaHashKeys: ["a", "b"]),
      try deriveMediaMessageId(
        conversationKey: conversationKey,
        conversationKeyVersion: "8", senderId: "1001",
        conversationId: "1001:1002", mediaHashKeys: ["a", "b"]),
      try deriveMediaMessageId(
        conversationKey: conversationKey,
        conversationKeyVersion: "7", senderId: "1002",
        conversationId: "1001:1002", mediaHashKeys: ["a", "b"]),
      try deriveMediaMessageId(
        conversationKey: conversationKey,
        conversationKeyVersion: "7", senderId: "1001",
        conversationId: "1001:1003", mediaHashKeys: ["a", "b"]),
      try deriveMediaMessageId(
        conversationKey: conversationKey,
        conversationKeyVersion: "7", senderId: "1001",
        conversationId: "1001:1002", mediaHashKeys: ["b", "a"]),
      try deriveMediaMessageId(
        conversationKey: conversationKey,
        conversationKeyVersion: "7", senderId: "1001",
        conversationId: "1001:1002", mediaHashKeys: ["ab"]),
    ]
    for (index, variant) in variants.enumerated() {
      XCTAssertNotEqual(base, variant, "variant \(index)")
    }
  }
}
