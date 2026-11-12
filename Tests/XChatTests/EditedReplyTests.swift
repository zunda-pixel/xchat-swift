import Testing

@testable import XChat

@Test(arguments: [true, false])
func v0ReplyPreviewBindsTheEditToTheOriginalSequenceId(matches: Bool) throws {
  let core = XChatCore()
  let privateKey = TestVectors.bytes("signing_private_b64")
  let key = TestVectors.bytes("conversation_key_b64")
  let version = TestVectors.string("event_signing_key_version")
  let sender = TestVectors.string("event_sender_id")
  let conversation = TestVectors.string("event_conversation_id")
  let original = try core.parseEvent(TestVectors.string("event_message_b64"))
  let sequenceId = try #require(original.sequenceId)
  try core.importKeys(
    identityPrivateKey: TestVectors.bytes("identity_private_b64"),
    signingPrivateKey: privateKey, publicKeyVersion: version)
  let edit = try core.encryptEdit(
    targetMessageSequenceId: matches ? sequenceId : sequenceId + "1",
    updatedText: "edited",
    targetMessageId: nil,
    conversationId: conversation,
    conversationKey: key,
    conversationKeyVersion: "1001",
    senderId: sender)
  let preview = ReplyingToPreview(
    messageText: "edited", rawEventMessageCreate: original,
    rawEventEditMessage: try core.parseEvent(edit.eventB64))
  var holder = MessageEntryHolder()
  holder.contents = .message(MessageContents(messageText: "reply", replyingToPreview: preview))
  var writer = ThriftWriter()
  holder.write(to: &writer)

  let messageId = "011a89ed-92fc-4148-871b-0a1cb30aa101"
  let detail = MessageEventDetail.messageCreate(
    MessageCreateEvent(
      contents: try encryptMessage(key: key, plaintext: writer.data),
      conversationKeyVersion: "1001"))
  let signature = try signEventSignature(
    signingPrivateKey: privateKey, publicKeyVersion: version, messageId: messageId,
    senderId: sender, conversationId: conversation, signatureVersion: currentSignatureVersion,
    detail: detail)
  let reply = MessageEvent(
    messageId: messageId, senderId: sender, conversationId: conversation, detail: detail,
    messageEventSignature: signature.signature)
  var eventWriter = ThriftWriter()
  reply.write(to: &eventWriter)
  let result = try core.decryptEvent(
    Base64.encodeStandard(eventWriter.data),
    conversationKeys: ["1001": key],
    signingKeys: [
      SigningKeyEntry(
        userId: sender, publicKeyVersion: version,
        publicKey: TestVectors.string("signing_public_b64"))
    ])
  guard case .message(let message) = result else {
    Issue.record("Expected a reply message")
    return
  }
  #expect(message.replyPreviewValidation == (matches ? .valid : .invalid))
}
