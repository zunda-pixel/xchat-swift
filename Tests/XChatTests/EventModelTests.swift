import XCTest

@testable import XChat

/// The typed event and content models against the cross-binding vectors:
/// envelopes, message contents, key changes, and every payload
/// encrypted under the conversation key or a per-message key.
final class EventModelTests: XCTestCase {
  private func decodeEvent(_ field: String) throws -> MessageEvent {
    var reader = ThriftReader(TestVectors.bytes(field))
    let event = try MessageEvent.read(&reader)
    XCTAssertTrue(reader.isAtEnd)
    return event
  }

  private func parseHolder(_ bytes: [UInt8]) throws -> MessageEntryHolder {
    var reader = ThriftReader(bytes)
    let holder = try MessageEntryHolder.read(&reader)
    XCTAssertTrue(reader.isAtEnd)
    return holder
  }

  private func messageCreate(_ event: MessageEvent) throws -> MessageCreateEvent {
    guard case .messageCreate(let create) = try XCTUnwrap(event.detail) else {
      XCTFail("expected a message-create detail")
      throw XChatError.parse("not a message-create detail")
    }
    return create
  }

  private func text(_ contents: MessageEntryContents?) -> String? {
    guard case .message(let message) = contents else { return nil }
    return message.messageText
  }

  // MARK: Conversation-key messages (v0)

  /// Decodes the message event and decrypts its contents under the
  /// conversation key the vector names.
  func testVectorMessageEventDecryptsUnderConversationKey() throws {
    let event = try decodeEvent("event_message_b64")
    XCTAssertEqual(event.messageId?.count, 36)
    XCTAssertEqual(event.senderId, TestVectors.string("event_sender_id"))
    XCTAssertEqual(event.conversationId, TestVectors.string("event_conversation_id"))
    XCTAssertEqual(event.createdAtMilliseconds, "1700000000000")

    let create = try messageCreate(event)
    XCTAssertEqual(create.conversationKeyVersion, "1001")
    XCTAssertNil(create.contentsEncryptionVersion)
    let contents = try XCTUnwrap(create.contents)

    let plaintext = try decryptMessage(
      key: TestVectors.bytes("conversation_key_b64"), ciphertext: contents)
    let holder = try parseHolder(plaintext)
    XCTAssertEqual(text(holder.contents), TestVectors.string("event_message_text"))
    guard case .message(let message) = try XCTUnwrap(holder.contents) else {
      return XCTFail("expected a text message")
    }
    XCTAssertNil(message.entities)
    XCTAssertNil(message.attachments)
  }

  // MARK: Per-message-key messages (v1)

  /// The v1 vector: contents_encryption_version 1 means the contents are
  /// encrypted under a key derived from the sender and message id, which
  /// the vector gives as a known answer.
  func testVectorMessageEventDecryptsUnderMessageKey() throws {
    let event = try decodeEvent("event_message_key_b64")
    let create = try messageCreate(event)
    XCTAssertEqual(create.contentsEncryptionVersion, 1)
    XCTAssertEqual(
      create.conversationKeyVersion,
      TestVectors.string("message_key_conversation_key_version"))

    let messageKey = try deriveMessageKey(
      conversationKey: try Hex.decode(
        TestVectors.string("message_key_conversation_key_hex")),
      senderId: try XCTUnwrap(event.senderId),
      messageId: try XCTUnwrap(event.messageId))
    XCTAssertEqual(event.senderId, TestVectors.string("message_key_sender_id"))
    XCTAssertEqual(
      Hex.encode(messageKey),
      "4d443b9a862e9584ccd0aee2753162aa7c5c1dbcb5f967610155f65ae41d8084")

    let plaintext = try decryptMessage(
      key: messageKey, ciphertext: try XCTUnwrap(create.contents))
    let holder = try parseHolder(plaintext)
    XCTAssertEqual(text(holder.contents), TestVectors.string("event_message_key_text"))
  }

  /// The same path with a short sender id.
  func testVectorShortMessageEventDecryptsUnderMessageKey() throws {
    let event = try decodeEvent("event_message_key_short_b64")
    let create = try messageCreate(event)
    XCTAssertEqual(create.contentsEncryptionVersion, 1)

    let messageKey = try deriveMessageKey(
      conversationKey: try Hex.decode(
        TestVectors.string("message_key_short_conversation_key_hex")),
      senderId: try XCTUnwrap(event.senderId),
      messageId: try XCTUnwrap(event.messageId))
    XCTAssertEqual(event.senderId, TestVectors.string("message_key_short_sender_id"))

    let plaintext = try decryptMessage(
      key: messageKey, ciphertext: try XCTUnwrap(create.contents))
    let holder = try parseHolder(plaintext)
    XCTAssertEqual(
      text(holder.contents), TestVectors.string("event_message_key_short_text"))
  }

  // MARK: Key changes

  /// Decodes the key-change event and decrypts its participant key with
  /// the vector's identity key.
  func testVectorKeyChangeEvent() throws {
    let event = try decodeEvent("event_key_change_b64")
    XCTAssertEqual(event.messageId, "kc-msg-1")
    guard case .conversationKeyChange(let change) = try XCTUnwrap(event.detail) else {
      return XCTFail("expected a conversation-key-change detail")
    }
    XCTAssertEqual(change.conversationKeyVersion, "1001")
    let participants = try XCTUnwrap(change.conversationParticipantKeys)
    XCTAssertEqual(participants.count, 1)
    let participant = try XCTUnwrap(participants.first)
    XCTAssertEqual(participant.userId, "1111")
    XCTAssertEqual(
      participant.publicKeyVersion, TestVectors.string("event_recipient_key_version"))

    let encrypted = try Base64.decodeStandard(
      try XCTUnwrap(participant.encryptedConversationKey))
    let conversationKey = try decryptWithPrivateKey(
      privateKey: TestVectors.bytes("identity_private_b64"), data: encrypted)
    XCTAssertEqual(conversationKey, TestVectors.bytes("conversation_key_b64"))
  }

  // MARK: Other event variants

  func testVectorFailureEvent() throws {
    let event = try decodeEvent("event_failure_b64")
    XCTAssertEqual(event.messageId, "failure-msg-1")
    guard case .messageFailure(let failure) = try XCTUnwrap(event.detail) else {
      return XCTFail("expected a message-failure detail")
    }
    XCTAssertNotNil(failure.failureType)
  }

  /// An unencrypted message has no conversation-key version; its contents
  /// are already plaintext Thrift bytes.
  func testVectorUnencryptedEvent() throws {
    let event = try decodeEvent("event_unencrypted_b64")
    XCTAssertEqual(event.messageId, "plain-msg-1")
    let create = try messageCreate(event)
    XCTAssertNil(create.conversationKeyVersion)
    let holder = try parseHolder(try XCTUnwrap(create.contents))
    XCTAssertNotNil(text(holder.contents))
  }

  // MARK: Serialization round trips

  /// The send path: every modelled struct survives a write/read round trip
  /// unchanged.
  func testMessageContentRoundTrip() throws {
    let entity = RichTextEntity(
      startIndex: 0, endIndex: 5, content: .mention)
    let media = MediaAttachment(
      mediaHashKey: "hash-1",
      dimensions: MediaDimensions(width: 100, height: 50),
      type: .image,
      durationMilliseconds: nil,
      filesizeBytes: 1234,
      filename: "a.jpg",
      attachmentId: "att-1",
      legacyMediaURLHTTPS: nil,
      legacyMediaPreviewURL: nil,
      grokTag: nil,
      plaintextSHA256: [1, 2, 3])
    let url = UrlAttachment(
      url: "https://example.com",
      bannerImage: UrlAttachmentImage(
        mediaHashKey: "banner", filesizeBytes: 1, filename: "b.png",
        dimensions: nil),
      faviconImage: nil,
      displayTitle: "Example",
      attachmentId: nil)
    let preview = ReplyingToPreview(
      senderId: 42,
      messageText: "quoted",
      entities: [entity],
      attachments: [.media(media)],
      senderDisplayName: "Someone",
      messageSequenceId: "7",
      messageId: "msg-7",
      attachmentId: nil)
    let quickReply = QuickReply.request(
      QuickReplyRequest(
        options: QuickReplyOptionsRequest(
          id: "qr-1",
          options: [
            QuickReplyOption(id: "a", label: "A", metadata: nil, optionDescription: "first"),
            QuickReplyOption(id: "b", label: "B", metadata: "m", optionDescription: nil),
          ])))
    let contents = MessageContents(
      messageText: "hello",
      entities: [entity],
      attachments: [
        .media(media), .url(url),
        .post(
          PostAttachment(restId: "1", postURL: "u", attachmentId: "2")),
      ],
      replyingToPreview: preview,
      forwardedMessage: ForwardedMessage(messageText: "fwd", entities: [entity]),
      sentFrom: 1,
      quickReply: quickReply,
      callToActions: [CallToAction(label: "go", url: "https://x")],
      additionalFields: ["k": "v"])
    let holder = MessageEntryHolder(contents: .message(contents))

    var writer = ThriftWriter()
    holder.write(to: &writer)
    let parsed = try parseHolder(writer.data)
    XCTAssertEqual(parsed, holder)
  }

  func testEventRoundTrip() throws {
    let create = MessageCreateEvent(
      contents: [9, 8, 7],
      conversationKeyVersion: "1001",
      shouldNotify: true,
      ttlMilliseconds: 60_000,
      deliveredAtMilliseconds: nil,
      isPendingPublicKey: nil,
      isMessageRequest: false,
      contentsEncryptionVersion: 1)
    let signature = MessageEventSignature(
      signature: "c2ln",
      publicKeyVersion: "1",
      signatureVersion: "10",
      signingPublicKey: "cG9r",
      messageSigningKeyInfoList: nil)
    let event = MessageEvent(
      sequenceId: "5",
      messageId: "msg-1",
      senderId: "1111",
      conversationId: "1111:2222",
      conversationToken: nil,
      createdAtMilliseconds: "1700000000000",
      detail: .messageCreate(create),
      relaySource: nil,
      messageEventSignature: signature,
      previousSequenceId: "4",
      isTrusted: true,
      conversationEventCounter: nil)

    var writer = ThriftWriter()
    event.write(to: &writer)
    var reader = ThriftReader(writer.data)
    let parsed = try MessageEvent.read(&reader)
    XCTAssertTrue(reader.isAtEnd)
    XCTAssertEqual(parsed, event)
  }

  func testReactionAndEditPayloadRoundTrip() throws {
    let reaction = MessageEntryHolder(
      contents: .reactionAdd(
        MessageReactionAdd(
          messageSequenceId: "5", emoji: "👍", messageAttachmentId: nil)))
    let edit = MessageEntryHolder(
      contents: .messageEdit(
        MessageEdit(
          messageSequenceId: "5",
          updatedText: "new",
          entities: [RichTextEntity(startIndex: 0, endIndex: 3, content: .hashtag)],
          messageId: "msg-5")))
    let readMarker = MessageEntryHolder(
      contents: .markConversationRead(
        MarkConversationRead(seenUntilSequenceId: "9", seenAtMilliseconds: 1)))

    for holder in [reaction, edit, readMarker] {
      var writer = ThriftWriter()
      holder.write(to: &writer)
      XCTAssertEqual(try parseHolder(writer.data), holder)
    }
  }

  /// A union variant this SDK does not model is read as `.unsupported`
  /// with its tag, so callers can tell it apart from modelled events.
  func testUnmodelledDetailIsReportedByFieldId() throws {
    var writer = ThriftWriter()
    writer.writeFieldBegin(id: 17, type: .structure)
    writer.writeFieldStop()
    writer.writeFieldStop()

    var reader = ThriftReader(writer.data)
    let detail = try MessageEventDetail.read(&reader)
    XCTAssertEqual(detail, .unsupported(fieldId: 17))

    var contentsWriter = ThriftWriter()
    contentsWriter.writeFieldBegin(id: 17, type: .structure)
    contentsWriter.writeFieldStop()
    contentsWriter.writeFieldStop()
    var contentsReader = ThriftReader(contentsWriter.data)
    let contents = try MessageEntryContents.read(&contentsReader)
    XCTAssertEqual(contents, .unsupported(fieldId: 17))
  }
}
