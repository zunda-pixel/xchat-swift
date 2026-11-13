import Testing

@testable import XChat

enum EditedPreviewCase: CaseIterable {
  case shortPrefix
  case unsignedEditTarget
  case authenticPrefix
  case authenticFullText
  case forgedSuffix
  case forgedHash
  case omittedHash
  case matchingHash
}

@Test(arguments: EditedPreviewCase.allCases)
func v0ReplyPreviewRequiresAuthenticatedTextAndEditTarget(scenario: EditedPreviewCase) throws {
  let core = XChatCore()
  let privateKey = TestVectors.bytes("signing_private_b64")
  let key = TestVectors.bytes("conversation_key_b64")
  let version = TestVectors.string("event_signing_key_version")
  let sender = TestVectors.string("event_sender_id")
  let conversation = TestVectors.string("event_conversation_id")
  try core.importKeys(
    identityPrivateKey: TestVectors.bytes("identity_private_b64"),
    signingPrivateKey: privateKey, publicKeyVersion: version)
  let prefix = String(repeating: "🙂", count: 70)
  let text = prefix + " authentic suffix"
  let claimedText: String
  switch scenario {
  case .shortPrefix:
    claimedText = String(prefix.dropLast())
  case .authenticPrefix:
    claimedText = prefix
  case .forgedSuffix:
    claimedText = prefix + " forged suffix"
  default:
    claimedText = text
  }

  let media = MediaAttachment(
    mediaHashKey: "media", attachmentId: "attachment",
    plaintextSHA256: Array(repeating: 1, count: 32))
  var original = try makeReplyTestEvent(
    MessageContents(messageText: text, attachments: [.media(media)]),
    messageId: "011a89ed-92fc-4148-871b-0a1cb30aa102",
    sender: sender, conversation: conversation, version: version, key: key, privateKey: privateKey)
  var claimedMedia = media
  if scenario == .forgedHash {
    claimedMedia.plaintextSHA256 = Array(repeating: 2, count: 32)
  } else if scenario == .omittedHash {
    claimedMedia.plaintextSHA256 = nil
  }
  original.sequenceId = "7"
  var preview = ReplyingToPreview(
    messageText: claimedText, attachments: [.media(claimedMedia)],
    senderDisplayName: "Untrusted name", messageSequenceId: original.sequenceId,
    attachmentId: "untrusted-selection",
    rawEventMessageCreate: original)
  if scenario == .unsignedEditTarget {
    let edit = try core.encryptEdit(
      targetMessageSequenceId: "7", updatedText: text, targetMessageId: nil,
      conversationId: conversation, conversationKey: key,
      conversationKeyVersion: "1001", senderId: sender)
    preview.rawEventEditMessage = try core.parseEvent(edit.eventB64)
  }
  let reply = try makeReplyTestEvent(
    MessageContents(messageText: "reply", replyingToPreview: preview),
    messageId: "011a89ed-92fc-4148-871b-0a1cb30aa101",
    sender: sender, conversation: conversation, version: version, key: key, privateKey: privateKey)
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
  guard case .message(let message) = result, case .text(let content) = message.content else {
    Issue.record("Expected a reply message")
    return
  }
  let decodedPreview = try #require(content.replyingToPreview)
  #expect(decodedPreview.messageSequenceId == nil)
  #expect(decodedPreview.senderDisplayName == nil)
  #expect(decodedPreview.attachmentId == nil)
  let valid = [.authenticPrefix, .authenticFullText, .omittedHash, .matchingHash].contains(scenario)
  #expect(message.replyPreviewValidation == (valid ? .valid : .invalid))
}

private func makeReplyTestEvent(
  _ content: MessageContents, messageId: String, sender: String, conversation: String,
  version: String, key: [UInt8], privateKey: [UInt8]
) throws -> MessageEvent {
  var holder = MessageEntryHolder()
  holder.contents = .message(content)
  var writer = ThriftWriter()
  holder.write(to: &writer)

  let detail = MessageEventDetail.messageCreate(
    MessageCreateEvent(
      contents: try encryptMessage(key: key, plaintext: writer.data),
      conversationKeyVersion: "1001"))
  let signature = try signEventSignature(
    signingPrivateKey: privateKey, publicKeyVersion: version, messageId: messageId,
    senderId: sender, conversationId: conversation, signatureVersion: currentSignatureVersion,
    detail: detail)
  return MessageEvent(
    messageId: messageId, senderId: sender, conversationId: conversation, detail: detail,
    messageEventSignature: signature.signature)
}
