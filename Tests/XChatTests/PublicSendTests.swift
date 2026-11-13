import Testing
import XChat

@Test func quickReplyInputsCanBeConstructedByClients() {
  let option = QuickReplyOptionInfo(id: "yes", label: "Yes")
  let request = QuickReplyInfo(content: .request(id: "request", options: [option]))
  let response = QuickReplyInfo(
    content: .response(requestId: "request", metadata: nil, selectedOptionId: "yes"))
  #expect(request.content == .request(id: "request", options: [option]))
  #expect(
    response.content == .response(requestId: "request", metadata: nil, selectedOptionId: "yes"))
}

@Test func repliesUseTheQuotedMessagesKeyAfterRotation() throws {
  let oldVersion = TestVectors.string("message_key_conversation_key_version")
  let oldKey = try Hex.decode(TestVectors.string("message_key_conversation_key_hex"))
  let newVersion = "999999"
  let newKey = [UInt8](repeating: 0xa5, count: 32)
  let sender = TestVectors.string("event_sender_id")
  let quotedSender = TestVectors.string("message_key_sender_id")
  let publicKeyVersion = TestVectors.string("event_signing_key_version")
  let signingKeys = [sender, quotedSender].map {
    SigningKeyEntry(
      userId: $0, publicKeyVersion: publicKeyVersion,
      publicKey: TestVectors.string("signing_public_b64"))
  }

  let core = XChatCore()
  try core.importKeys(
    identityPrivateKey: TestVectors.bytes("identity_private_b64"),
    signingPrivateKey: TestVectors.bytes("signing_private_b64"),
    publicKeyVersion: publicKeyVersion)
  core.sendVersion = .v1

  let target = TestVectors.string("event_message_key_b64")
  let conversationId = TestVectors.string("event_conversation_id")
  let error = #expect(throws: XChatError.self) {
    try core.encryptReply(
      text: "after rotation", replyToEventB64: target, conversationId: conversationId,
      conversationKey: newKey, conversationKeyVersion: newVersion, senderId: sender)
  }
  #expect(error?.kind == .decryption)

  let wrongConversation = #expect(throws: XChatError.self) {
    try core.encryptReply(
      text: "after rotation", replyToEventB64: target, conversationId: "1111:3333",
      conversationKey: newKey, conversationKeyVersion: newVersion, senderId: sender,
      replyToConversationKeys: [oldVersion: oldKey])
  }
  #expect(wrongConversation?.kind == .invalidInput)

  let payload = try core.encryptReply(
    text: "after rotation", replyToEventB64: target, conversationId: conversationId,
    conversationKey: newKey, conversationKeyVersion: newVersion, senderId: sender,
    replyToConversationKeys: [oldVersion: oldKey])
  #expect(payload.conversationKeyVersion == newVersion)

  let event = try core.decryptEvent(
    payload.eventB64, conversationKeys: [newVersion: newKey], signingKeys: signingKeys)
  guard case .message(let message) = event, case .text(let content) = message.content else {
    Issue.record("Expected a text reply")
    return
  }
  #expect(message.text == "after rotation")
  #expect(message.replyPreviewValidation == .valid)
  #expect(content.replyingToPreview?.messageText == TestVectors.string("event_message_key_text"))
}

@Test(arguments: ["abc", "01", "-1", "9223372036854775808"])
func importingAnInvalidKeyVersionPreservesLoadedKeys(version: String) throws {
  let core = XChatCore()
  let identity = TestVectors.bytes("identity_private_b64")
  let signing = TestVectors.bytes("signing_private_b64")
  try core.importKeys(
    identityPrivateKey: identity, signingPrivateKey: signing, publicKeyVersion: "1")

  let error = #expect(throws: XChatError.self) {
    try core.importKeys(identityPrivateKey: signing, publicKeyVersion: version)
  }
  #expect(error?.kind == .invalidInput)
  let keys = try core.exportKeys()
  #expect(keys.identity == identity)
  #expect(keys.signing == signing)
  #expect(core.publicKeyVersion == "1")
}
