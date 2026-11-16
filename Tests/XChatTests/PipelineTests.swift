import Testing

@testable import XChat

/// One media file of the v1 vector message: its attachment position and the
/// fixture fields naming its hash key, ciphertext, and plaintext.
struct MediaFileCase: Sendable {
  var index: Int
  var hashField: String
  var encryptedField: String
  var plaintextField: String
}

private let mediaFileCases: [MediaFileCase] = [
  MediaFileCase(
    index: 0, hashField: "media_first_hash_key",
    encryptedField: "media_first_encrypted_b64",
    plaintextField: "media_first_plaintext_b64"),
  MediaFileCase(
    index: 1, hashField: "media_second_hash_key",
    encryptedField: "media_second_encrypted_b64",
    plaintextField: "media_second_plaintext_b64"),
]

/// The decryption pipeline: single events, batches, conversation-key
/// adoption with its monotonic floor, media hash collection, and reply
/// preview validation — all against the core's cross-binding vectors.
struct PipelineTests {
  private func signingKey(userId: String) -> SigningKeyEntry {
    SigningKeyEntry(
      userId: userId,
      publicKeyVersion: TestVectors.string("event_signing_key_version"),
      publicKey: TestVectors.string("signing_public_b64"))
  }

  private func makeCore(rejectUnverified: Bool = true) throws -> XChatCore {
    let core = XChatCore(rejectUnverified: rejectUnverified)
    try core.importKeys(
      identityPrivateKey: TestVectors.bytes("identity_private_b64"),
      signingPrivateKey: TestVectors.bytes("signing_private_b64"),
      publicKeyVersion: TestVectors.string("event_recipient_key_version"))
    return core
  }

  private func encodeEvent(_ event: MessageEvent) -> String {
    var writer = ThriftWriter()
    event.write(to: &writer)
    return Base64.encodeStandard(writer.data)
  }

  private func message(_ event: XChatEvent) throws -> Message {
    let message: Message? =
      switch event {
      case .message(let message): message
      default: nil
      }
    return try #require(message, "expected a message event, got \(event)")
  }

  // MARK: Single events

  @Test func decryptsConversationKeyMessage() throws {
    let core = XChatCore()
    let event = try core.decryptEvent(
      TestVectors.string("event_message_b64"),
      conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
      signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])

    let message = try message(event)
    #expect(message.text == TestVectors.string("event_message_text"))
    #expect(message.verified)
    #expect(message.conversationKeyVersion == "1001")
    #expect(message.meta.senderId == TestVectors.string("event_sender_id"))
    #expect(message.meta.conversationId == TestVectors.string("event_conversation_id"))
    #expect(message.meta.createdAtMilliseconds == 1_700_000_000_000)
    #expect(message.attachments == [])
    #expect(message.mediaHashes == [])
  }

  @Test func decryptsMessageKeyMessage() throws {
    let keyVersion = TestVectors.string("message_key_conversation_key_version")
    let event = try XChatCore().decryptEvent(
      TestVectors.string("event_message_key_b64"),
      conversationKeys: [
        keyVersion: try Hex.decode(
          TestVectors.string("message_key_conversation_key_hex"))
      ],
      signingKeys: [signingKey(userId: TestVectors.string("message_key_sender_id"))])

    let message = try message(event)
    #expect(message.text == TestVectors.string("event_message_key_text"))
    #expect(message.verified)
    #expect(message.conversationKeyVersion == keyVersion)
  }

  @Test func missingConversationKeyThrows() {
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(.message, version: "1001", available: []))
    ) {
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])
    }
  }

  @Test func unverifiedMessageIsRejectedByDefault() throws {
    let wrongKey = SigningKeyEntry(
      userId: TestVectors.string("event_sender_id"),
      publicKeyVersion: "99",
      publicKey: TestVectors.string("signing_public_b64"))
    #expect(throws: XChatError.verification(.unverifiable(.message))) {
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [wrongKey])
    }

    // With the policy off the message decrypts, marked unverified.
    let permissive = XChatCore(rejectUnverified: false)
    let message = try message(
      permissive.decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [wrongKey]))
    #expect(!message.verified)
    #expect(message.text == TestVectors.string("event_message_text"))
  }

  @Test func garbageEventThrowsParse() {
    #expect(
      throws: XChatError.parse(.event(.base64(.invalidByte(UInt8(ascii: "!")))))
    ) {
      try XChatCore().decryptEvent(TestVectors.string("event_garbage_b64"))
    }
  }

  // MARK: Batches and key changes

  @Test func batchAdoptsKeyChangeAndDecrypts() throws {
    let core = try makeCore()
    let result = core.decryptEvents(
      [
        TestVectors.string("event_key_change_b64"),
        TestVectors.string("event_message_b64"),
        TestVectors.string("event_garbage_b64"),
      ],
      signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])

    #expect(
      result.errors == [2: .parse(.event(.base64(.invalidByte(UInt8(ascii: "!")))))])
    #expect(
      result.conversationKeys.keys["1001"]
        == TestVectors.bytes("conversation_key_b64"))
    #expect(result.conversationKeys.latestVersion == "1001")
    #expect(result.events.count == 2)

    guard case .keyChange(let keyChange) = result.events[0].event else {
      Issue.record("expected the key change first")
      return
    }
    #expect(keyChange.verified)
    #expect(keyChange.conversationKeyVersion == "1001")
    #expect(keyChange.participantKeys.count == 1)

    let message = try message(result.events[1].event)
    #expect(message.text == TestVectors.string("event_message_text"))
    #expect(message.verified)
  }

  @Test(arguments: [false, true])
  func batchAdoptsOnlyTheKeyFromTheVerifiedEvent(unsignedFirst: Bool) throws {
    let core = try makeCore()
    let encoded = TestVectors.string("event_key_change_b64")
    let signing = signingKey(userId: TestVectors.string("event_sender_id"))
    var unsigned = try core.parseEvent(encoded)
    unsigned.messageEventSignature = nil
    let extractedChange: ConversationKeyChangeEvent? =
      switch unsigned.detail {
      case .conversationKeyChange(let change)?: change
      default: nil
      }
    var change = try #require(extractedChange, "expected key change")
    var participants = try #require(change.conversationParticipantKeys)
    #expect(participants.count == 1, "expected one participant")
    participants[0].encryptedConversationKey = Base64.encodeStandard(
      try encryptWithPublicKey(
        publicKey: TestVectors.bytes("identity_public_b64"),
        data: [UInt8](repeating: 42, count: 32)))
    change.conversationParticipantKeys = participants
    unsigned.detail = .conversationKeyChange(change)
    let unsignedEvent = encodeEvent(unsigned)

    let rejected = core.decryptEvents([unsignedEvent], signingKeys: [signing])
    #expect(rejected.conversationKeys.keys.isEmpty)
    #expect(rejected.errors == [0: .verification(.unverifiable(.keyChange))])
    let inspection = try makeCore(rejectUnverified: false)
      .decryptEvents([unsignedEvent], signingKeys: [signing])
    #expect(inspection.events.count == 1)
    #expect(inspection.conversationKeys.keys.isEmpty)

    let keyEvents = unsignedFirst ? [unsignedEvent, encoded] : [encoded, unsignedEvent]
    let result = core.decryptEvents(
      keyEvents + [TestVectors.string("event_message_b64")], signingKeys: [signing])
    let unsignedIndex = unsignedFirst ? 0 : 1
    #expect(result.errors == [unsignedIndex: .verification(.unverifiable(.keyChange))])
    #expect(
      result.conversationKeys.keys["1001"] == TestVectors.bytes("conversation_key_b64"))
    let decrypted = try message(try #require(result.events.last).event)
    #expect(decrypted.text == TestVectors.string("event_message_text"))
  }

  @Test func keyChangeCanVerifyWithAnExplicitKey() throws {
    let core = XChatCore()
    let encoded = TestVectors.string("event_key_change_b64")
    let keys = ["1001": TestVectors.bytes("conversation_key_b64")]
    let signing = signingKey(userId: TestVectors.string("event_sender_id"))
    let event = try core.decryptEvent(encoded, conversationKeys: keys, signingKeys: [signing])
    guard case .keyChange(let change) = event else {
      Issue.record("expected key change")
      return
    }
    #expect(change.verified)

    let batch = core.decryptEvents([encoded], conversationKeys: keys, signingKeys: [signing])
    #expect(batch.errors.isEmpty)
    #expect(batch.conversationKeys.keys == keys)
    #expect(batch.conversationKeys.latestVersion == nil)
  }

  /// An older, validly signed key change cannot lower the reported latest
  /// version, though its key is still adopted for decryption.
  @Test func keyVersionFloorIsMonotonic() throws {
    let core = try makeCore()
    let signing = signingKey(userId: TestVectors.string("event_sender_id"))

    let first = core.decryptEvents(
      [TestVectors.string("event_key_change_b64")], signingKeys: [signing])
    #expect(first.conversationKeys.latestVersion == "1001")

    // A crafted older key change, signed like the fixture's.
    let olderKey = randomBytes(32)
    let identityPublic = TestVectors.bytes("identity_public_b64")
    let encrypted = try encryptWithPublicKey(publicKey: identityPublic, data: olderKey)
    let detail = MessageEventDetail.conversationKeyChange(
      ConversationKeyChangeEvent(
        conversationKeyVersion: "500",
        conversationParticipantKeys: [
          ConversationParticipantKey(
            userId: "1111",
            encryptedConversationKey: Base64.encodeStandard(encrypted),
            publicKeyVersion: TestVectors.string("event_recipient_key_version"))
        ],
        forKeyRotation: nil))
    let (signature, _) = try signEventSignature(
      signingPrivateKey: TestVectors.bytes("signing_private_b64"),
      publicKeyVersion: TestVectors.string("event_signing_key_version"),
      messageId: "kc-2",
      senderId: TestVectors.string("event_sender_id"),
      conversationId: TestVectors.string("event_conversation_id"),
      signatureVersion: 7,
      detail: detail,
      plaintextConversationKeyB64: Base64.encodeStandard(olderKey))
    let older = MessageEvent(
      sequenceId: "3",
      messageId: "kc-2",
      senderId: TestVectors.string("event_sender_id"),
      conversationId: TestVectors.string("event_conversation_id"),
      createdAtMilliseconds: "1700000000001",
      detail: detail,
      messageEventSignature: signature)

    let second = core.decryptEvents([encodeEvent(older)], signingKeys: [signing])
    #expect(second.errors.isEmpty)
    #expect(second.conversationKeys.keys["500"] == olderKey)
    #expect(
      second.conversationKeys.latestVersion == "1001",
      "a replayed older key change must not lower the floor")
  }

  // MARK: Reply previews

  @Test func replyPreviewValidation() throws {
    let core = try makeCore()
    let result = core.decryptEvents(
      [
        TestVectors.string("event_key_change_b64"),
        TestVectors.string("event_reply_valid_b64"),
        TestVectors.string("event_reply_forged_b64"),
      ],
      signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])

    #expect(result.errors.isEmpty, "errors: \(result.errors)")
    let messages = result.events.compactMap { event -> Message? in
      guard case .message(let message) = event.event else { return nil }
      return message
    }
    #expect(messages.count == 2)
    #expect(messages[0].text == TestVectors.string("event_reply_text"))
    #expect(messages[0].replyPreviewValidation == .valid)
    #expect(messages[1].replyPreviewValidation == .invalid)
  }

  // MARK: Media

  /// The message's media hash keys, in attachment order.
  @Test func mediaHashesInAttachmentOrder() throws {
    let keyVersion = TestVectors.string("message_key_conversation_key_version")
    let event = try XChatCore().decryptEvent(
      TestVectors.string("event_message_key_b64"),
      conversationKeys: [
        keyVersion: try Hex.decode(
          TestVectors.string("message_key_conversation_key_hex"))
      ],
      signingKeys: [signingKey(userId: TestVectors.string("message_key_sender_id"))])
    let message = try message(event)

    #expect(
      message.mediaHashes.map(\.mediaHashKey)
        == [
          TestVectors.string("media_first_hash_key"),
          TestVectors.string("media_second_hash_key"),
        ])
    #expect(message.mediaHashes.map(\.source) == ["media", "media"])
  }

  /// Each file decrypts under the key derived from the message key and the
  /// attachment's id.
  @Test(arguments: mediaFileCases)
  func mediaAttachmentKeyDecrypts(file: MediaFileCase) throws {
    let keyVersion = TestVectors.string("message_key_conversation_key_version")
    let event = try XChatCore().decryptEvent(
      TestVectors.string("event_message_key_b64"),
      conversationKeys: [
        keyVersion: try Hex.decode(
          TestVectors.string("message_key_conversation_key_hex"))
      ],
      signingKeys: [signingKey(userId: TestVectors.string("message_key_sender_id"))])
    let message = try message(event)

    let conversationKey = try Hex.decode(
      TestVectors.string("message_key_conversation_key_hex"))
    let messageId = try #require(message.meta.messageId)
    let messageKey = try #require(
      deriveMessageKey(
        conversationKey: conversationKey,
        senderId: TestVectors.string("message_key_sender_id"),
        messageId: messageId))

    let hash = TestVectors.string(file.hashField)
    let extractedAttachment: MediaAttachmentInfo? =
      switch message.attachments.first(where: {
        guard case .media(let media) = $0 else { return false }
        return media.mediaHashKey == hash
      }) {
      case .media(let media)?: media
      default: nil
      }
    let attachment = try #require(
      extractedAttachment, "attachment for \(hash) is missing")

    let attachmentId = resolveAttachmentId(
      storedId: attachment.attachmentId, messageId: message.meta.messageId ?? "",
      index: file.index)
    let attachmentKey = deriveAttachmentKey(
      messageKey: messageKey, attachmentId: attachmentId)
    #expect(
      try decryptFile(
        key: attachmentKey,
        ciphertext: TestVectors.bytes(file.encryptedField))
        == TestVectors.bytes(file.plaintextField),
      "\(file.hashField)")
  }

  // MARK: Other variants

  @Test func typingEvent() throws {
    let event = MessageEvent(
      senderId: "1111",
      conversationId: "1111:2222",
      detail: .messageTyping(
        MessageTypingEvent(
          conversationId: "1111:2222", activityType: 1, isGrok: false,
          createdAtMilliseconds: "1700000000000")))
    guard case .typing(let typing) = try XChatCore().decryptEvent(encodeEvent(event))
    else {
      Issue.record("expected a typing event")
      return
    }
    #expect(typing.activityType == 1)
    #expect(typing.meta.senderId == "1111")
  }

  @Test func failureEvent() throws {
    let event = try XChatCore().decryptEvent(TestVectors.string("event_failure_b64"))
    guard case .failure(let failure) = event else {
      Issue.record("expected a failure event")
      return
    }
    #expect(failure.failureType != nil)
    #expect(failure.meta.messageId == "failure-msg-1")
  }

  /// A read marker (a detail variant this SDK does not model) decrypts to
  /// an unsupported event rather than failing the batch.
  @Test func unsupportedDetailEvent() throws {
    var writer = ThriftWriter()
    writer.writeFieldBegin(id: 2, type: .binary)
    writer.writeString("read-msg")
    writer.writeFieldBegin(id: 3, type: .binary)
    writer.writeString("1111")
    writer.writeFieldBegin(id: 7, type: .structure)
    writer.writeFieldBegin(id: 12, type: .structure)  // MarkConversationReadEvent
    writer.writeFieldBegin(id: 1, type: .binary)
    writer.writeString("9")
    writer.writeFieldStop()  // end the read event
    writer.writeFieldStop()  // end the detail union
    writer.writeFieldStop()  // end the event
    let eventB64 = Base64.encodeStandard(writer.data)

    guard case .unsupported(let unsupported) = try XChatCore().decryptEvent(eventB64) else {
      Issue.record("expected an unsupported event")
      return
    }
    #expect(unsupported.meta.messageId == "read-msg")
    #expect(!unsupported.verified)
  }

  // MARK: Key bindings

  /// A signing key whose identity binding does not verify is dropped, so it
  /// cannot verify events; a valid binding verifies.
  @Test func signingKeyBindingFiltering() throws {
    let identityB64 = TestVectors.string("identity_public_b64")
    let identityBytes = TestVectors.bytes("identity_public_b64")
    let signingPrivate = TestVectors.bytes("signing_private_b64")
    let identityPrivate = TestVectors.bytes("identity_private_b64")
    let senderId = TestVectors.string("event_sender_id")

    let signingSPKI = try spkiDER(publicKey: TestVectors.bytes("signing_public_b64"))
    let goodSignature = try sign(privateKey: identityPrivate, payload: signingSPKI)
    let boundKey = SigningKeyEntry(
      userId: senderId,
      publicKeyVersion: TestVectors.string("event_signing_key_version"),
      publicKey: TestVectors.string("signing_public_b64"),
      identityPublicKey: identityB64,
      signingPublicKeySignature: Base64.encodeStandard(goodSignature))
    let message = try message(
      XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [boundKey]))
    #expect(message.verified)

    // A signature made by the signing key itself cannot establish identity authorization.
    let badSignature = try sign(privateKey: signingPrivate, payload: identityBytes)
    let unauthorized = [
      SigningKeyEntry(
        userId: senderId,
        publicKeyVersion: TestVectors.string("event_signing_key_version"),
        publicKey: TestVectors.string("signing_public_b64"),
        identityPublicKey: identityB64,
        identityPublicKeySignature: Base64.encodeStandard(badSignature)),
      SigningKeyEntry(
        userId: senderId,
        publicKeyVersion: TestVectors.string("event_signing_key_version"),
        publicKey: TestVectors.string("signing_public_b64"),
        identityPublicKey: identityB64,
        signingPublicKeySignature: Base64.encodeStandard(
          try sign(privateKey: signingPrivate, payload: signingSPKI))),
    ]
    for key in unauthorized {
      #expect(throws: XChatError.verification(.unverifiable(.message))) {
        try XChatCore().decryptEvent(
          TestVectors.string("event_message_b64"),
          conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
          signingKeys: [key])
      }
    }
  }
}
