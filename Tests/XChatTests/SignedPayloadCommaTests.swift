import Testing

@testable import XChat

/// A comma that a combining mark (U+0301) follows: one `Character`, which
/// is not `","`, so `String.contains(",")` does not find it, while its
/// UTF-8 holds the comma byte the signed payload is joined with.
private let commaWithMark = ",\u{301}"

/// A conversation id holding a comma that a combining mark follows is
/// refused by every send and by a key change, as a bare comma is, before
/// what they build: signed, its payload would hold the comma byte.
@Test func aCommaThatACombiningMarkFollowsIsRefusedBySends() throws {
  let conversationId = "1111\(commaWithMark)2222"
  #expect(!conversationId.contains(","))
  let refused = XChatError.invalidInput(.conversationIdContainsComma(conversationId))
  let key = TestVectors.bytes("conversation_key_b64")
  let version = "1001"
  let sender = TestVectors.string("event_sender_id")
  let core = XChatCore()
  try core.importKeys(
    identityPrivateKey: TestVectors.bytes("identity_private_b64"),
    signingPrivateKey: TestVectors.bytes("signing_private_b64"),
    publicKeyVersion: "1")

  for sendVersion in [SendVersion.v0, .v1] {
    core.sendVersion = sendVersion
    #expect(throws: refused, "\(sendVersion)") {
      try core.encryptMessage(
        text: "x", conversationId: conversationId, conversationKey: key,
        conversationKeyVersion: version, senderId: sender)
    }
  }
  #expect(throws: refused) {
    try core.encryptReply(
      text: "x", replyToEventB64: TestVectors.string("event_message_b64"),
      conversationId: conversationId, conversationKey: key, conversationKeyVersion: version,
      senderId: sender)
  }
  #expect(throws: refused) {
    try core.encryptReaction(
      emoji: "x", targetMessageSequenceId: "5", conversationId: conversationId,
      conversationKey: key, conversationKeyVersion: version, senderId: sender)
  }
  #expect(throws: refused) {
    try core.encryptRemoveReaction(
      emoji: "x", targetMessageSequenceId: "5", conversationId: conversationId,
      conversationKey: key, conversationKeyVersion: version, senderId: sender)
  }
  #expect(throws: refused) {
    try core.encryptEdit(
      targetMessageSequenceId: "5", updatedText: "x", targetMessageId: nil,
      conversationId: conversationId, conversationKey: key, conversationKeyVersion: version,
      senderId: sender)
  }
  #expect(throws: refused) {
    try core.prepareConversationKeyChange(
      participants: [
        ConversationParticipantPublicKey(
          userId: sender, identityPublicKey: TestVectors.string("identity_public_b64"),
          publicKeyVersion: "1"),
        ConversationParticipantPublicKey(
          userId: "2222", identityPublicKey: TestVectors.string("identity_public_b64"),
          publicKeyVersion: "1"),
      ],
      conversationId: conversationId, senderId: sender, conversationKeyVersion: "5000")
  }
}

/// No payload is built from an event any of whose components holds a
/// comma, bare or followed by a combining mark, so its signature is not
/// checked and the event is unverifiable: the payload's bytes could be
/// read as other components.
@Test(arguments: [",", commaWithMark])
func aCommaInAComponentLeavesNoPayload(comma: String) throws {
  let detail = MessageEventDetail.messageCreate(
    MessageCreateEvent(
      contents: [1], conversationKeyVersion: "9", shouldNotify: nil, ttlMilliseconds: nil,
      deliveredAtMilliseconds: nil, isPendingPublicKey: nil, isMessageRequest: nil,
      contentsEncryptionVersion: nil))
  let signingKey = SigningKey(
    publicKeyVersion: "1", publicKey: TestVectors.string("signing_public_b64"))
  func event(_ change: (inout MessageEvent) -> Void) -> MessageEvent {
    var event = MessageEvent()
    event.messageId = "m"
    event.senderId = "1111"
    event.conversationId = "1111:2222"
    event.messageEventSignature = MessageEventSignature(
      signature: Base64.encodeStandard([UInt8](repeating: 1, count: 64)),
      publicKeyVersion: "1", signatureVersion: "7", signingPublicKey: nil,
      messageSigningKeyInfoList: nil)
    event.detail = detail
    change(&event)
    return event
  }

  // Without the comma the payload builds, and the signature is checked.
  #expect(eventSignaturePayload(event: event { _ in }, detail: detail) != nil)
  #expect(
    checkEventSignature(event: event { _ in }, detail: detail, signingKeys: [signingKey])
      == .failed(.mismatch(senderId: "1111", keyVersion: "1")))

  let events = [
    ("message id", event { $0.messageId = "m\(comma)1" }),
    ("sender id", event { $0.senderId = "1111\(comma)" }),
    ("conversation id", event { $0.conversationId = "1111\(comma)2222" }),
  ]
  for (component, event) in events {
    #expect(eventSignaturePayload(event: event, detail: detail) == nil, "\(component)")
    #expect(
      checkEventSignature(event: event, detail: detail, signingKeys: [signingKey])
        == .unverifiable, "\(component)")
  }
}

/// A received message whose conversation id holds a comma that a
/// combining mark follows is unverifiable, as one with a bare comma is,
/// rather than checked against a payload holding the comma byte.
@Test(arguments: [",", commaWithMark])
func aReceivedConversationIdWithACommaIsUnverifiable(comma: String) throws {
  let eventB64 = try rewritingEvent(TestVectors.string("event_message_b64")) {
    $0.conversationId = "1111\(comma)2222"
  }
  #expect(throws: XChatError.verification(.unverifiable(.message))) {
    try XChatCore().decryptEvent(
      eventB64, conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
      signingKeys: [
        SigningKeyEntry(
          userId: TestVectors.string("event_sender_id"),
          publicKeyVersion: TestVectors.string("event_signing_key_version"),
          publicKey: TestVectors.string("signing_public_b64"))
      ])
  }
}
