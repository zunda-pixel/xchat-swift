import XCTest

@testable import XChat

/// The decryption pipeline: single events, batches, conversation-key
/// adoption with its monotonic floor, media hash collection, and reply
/// preview validation — all against the core's cross-binding vectors.
final class PipelineTests: XCTestCase {
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
    guard case .message(let message) = event else {
      throw XChatError.parse("expected a message event")
    }
    return message
  }

  // MARK: Single events

  func testDecryptsConversationKeyMessage() throws {
    let core = XChatCore()
    let event = try core.decryptEvent(
      TestVectors.string("event_message_b64"),
      conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
      signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])

    let message = try message(event)
    XCTAssertEqual(message.text, TestVectors.string("event_message_text"))
    XCTAssertTrue(message.verified)
    XCTAssertEqual(message.conversationKeyVersion, "1001")
    XCTAssertEqual(message.meta.senderId, TestVectors.string("event_sender_id"))
    XCTAssertEqual(message.meta.conversationId, TestVectors.string("event_conversation_id"))
    XCTAssertEqual(message.meta.createdAtMilliseconds, 1_700_000_000_000)
    XCTAssertEqual(message.attachments, [])
    XCTAssertEqual(message.mediaHashes, [])
  }

  func testDecryptsMessageKeyMessage() throws {
    let keyVersion = TestVectors.string("message_key_conversation_key_version")
    let event = try XChatCore().decryptEvent(
      TestVectors.string("event_message_key_b64"),
      conversationKeys: [
        keyVersion: try Hex.decode(
          TestVectors.string("message_key_conversation_key_hex"))
      ],
      signingKeys: [signingKey(userId: TestVectors.string("message_key_sender_id"))])

    let message = try message(event)
    XCTAssertEqual(message.text, TestVectors.string("event_message_key_text"))
    XCTAssertTrue(message.verified)
    XCTAssertEqual(message.conversationKeyVersion, keyVersion)
  }

  func testMissingConversationKeyThrows() {
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])
    ) { error in
      let error = error as? XChatError
      XCTAssertEqual(error?.kind, .decryption)
      XCTAssertTrue(
        error?.message.hasPrefix(
          "Message encrypted with key version '1001' but no matching key found")
          ?? false,
        error?.message ?? "")
    }
  }

  func testUnverifiedMessageIsRejectedByDefault() throws {
    let wrongKey = SigningKeyEntry(
      userId: TestVectors.string("event_sender_id"),
      publicKeyVersion: "99",
      publicKey: TestVectors.string("signing_public_b64"))
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [wrongKey])
    ) { error in
      let error = error as? XChatError
      XCTAssertEqual(error?.kind, .verification)
      XCTAssertEqual(
        error?.message,
        "Message signature could not be verified: "
          + "signature missing or no matching signing key")
    }

    // With the policy off the message decrypts, marked unverified.
    let permissive = XChatCore(rejectUnverified: false)
    let message = try message(
      permissive.decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [wrongKey]))
    XCTAssertFalse(message.verified)
    XCTAssertEqual(message.text, TestVectors.string("event_message_text"))
  }

  func testGarbageEventThrowsParse() {
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(TestVectors.string("event_garbage_b64"))
    ) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }
  }

  // MARK: Batches and key changes

  func testBatchAdoptsKeyChangeAndDecrypts() throws {
    let core = try makeCore()
    let result = core.decryptEvents(
      [
        TestVectors.string("event_key_change_b64"),
        TestVectors.string("event_message_b64"),
        TestVectors.string("event_garbage_b64"),
      ],
      signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])

    XCTAssertEqual(result.errors.count, 1)
    XCTAssertNotNil(result.errors[2])
    XCTAssertEqual(
      result.conversationKeys.keys["1001"],
      TestVectors.bytes("conversation_key_b64"))
    XCTAssertEqual(result.conversationKeys.latestVersion, "1001")
    XCTAssertEqual(result.events.count, 2)

    guard case .keyChange(let keyChange) = result.events[0].event else {
      return XCTFail("expected the key change first")
    }
    XCTAssertTrue(keyChange.verified)
    XCTAssertEqual(keyChange.conversationKeyVersion, "1001")
    XCTAssertEqual(keyChange.participantKeys.count, 1)

    let message = try message(result.events[1].event)
    XCTAssertEqual(message.text, TestVectors.string("event_message_text"))
    XCTAssertTrue(message.verified)
  }

  func testBatchAdoptsOnlyTheKeyFromTheVerifiedEvent() throws {
    let core = try makeCore()
    let encoded = TestVectors.string("event_key_change_b64")
    let signing = signingKey(userId: TestVectors.string("event_sender_id"))
    var unsigned = try core.parseEvent(encoded)
    unsigned.messageEventSignature = nil
    guard case .conversationKeyChange(var change)? = unsigned.detail else {
      return XCTFail("expected key change")
    }
    var participants = try XCTUnwrap(change.conversationParticipantKeys)
    guard participants.count == 1 else { return XCTFail("expected one participant") }
    participants[0].encryptedConversationKey = Base64.encodeStandard(
      try encryptWithPublicKey(
        publicKey: TestVectors.bytes("identity_public_b64"),
        data: [UInt8](repeating: 42, count: 32)))
    change.conversationParticipantKeys = participants
    unsigned.detail = .conversationKeyChange(change)
    let unsignedEvent = encodeEvent(unsigned)

    let rejected = core.decryptEvents([unsignedEvent], signingKeys: [signing])
    XCTAssertTrue(rejected.conversationKeys.keys.isEmpty)
    XCTAssertNotNil(rejected.errors[0])
    let inspection = try makeCore(rejectUnverified: false)
      .decryptEvents([unsignedEvent], signingKeys: [signing])
    XCTAssertEqual(inspection.events.count, 1)
    XCTAssertTrue(inspection.conversationKeys.keys.isEmpty)

    for keyEvents in [[encoded, unsignedEvent], [unsignedEvent, encoded]] {
      let result = core.decryptEvents(
        keyEvents + [TestVectors.string("event_message_b64")], signingKeys: [signing])
      XCTAssertEqual(result.errors.count, 1)
      XCTAssertNotNil(result.errors[try XCTUnwrap(keyEvents.firstIndex(of: unsignedEvent))])
      XCTAssertEqual(
        result.conversationKeys.keys["1001"], TestVectors.bytes("conversation_key_b64"))
      let decrypted = try message(XCTUnwrap(result.events.last).event)
      XCTAssertEqual(decrypted.text, TestVectors.string("event_message_text"))
    }
  }

  func testKeyChangeCanVerifyWithAnExplicitKey() throws {
    let core = XChatCore()
    let encoded = TestVectors.string("event_key_change_b64")
    let keys = ["1001": TestVectors.bytes("conversation_key_b64")]
    let signing = signingKey(userId: TestVectors.string("event_sender_id"))
    let event = try core.decryptEvent(encoded, conversationKeys: keys, signingKeys: [signing])
    guard case .keyChange(let change) = event else { return XCTFail("expected key change") }
    XCTAssertTrue(change.verified)

    let batch = core.decryptEvents([encoded], conversationKeys: keys, signingKeys: [signing])
    XCTAssertTrue(batch.errors.isEmpty)
    XCTAssertEqual(batch.conversationKeys.keys, keys)
    XCTAssertNil(batch.conversationKeys.latestVersion)
  }

  /// An older, validly signed key change cannot lower the reported latest
  /// version, though its key is still adopted for decryption.
  func testKeyVersionFloorIsMonotonic() throws {
    let core = try makeCore()
    let signing = signingKey(userId: TestVectors.string("event_sender_id"))

    let first = core.decryptEvents(
      [TestVectors.string("event_key_change_b64")], signingKeys: [signing])
    XCTAssertEqual(first.conversationKeys.latestVersion, "1001")

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
    XCTAssertTrue(second.errors.isEmpty)
    XCTAssertEqual(second.conversationKeys.keys["500"], olderKey)
    XCTAssertEqual(
      second.conversationKeys.latestVersion, "1001",
      "a replayed older key change must not lower the floor")
  }

  // MARK: Reply previews

  func testReplyPreviewValidation() throws {
    let core = try makeCore()
    let result = core.decryptEvents(
      [
        TestVectors.string("event_key_change_b64"),
        TestVectors.string("event_reply_valid_b64"),
        TestVectors.string("event_reply_forged_b64"),
      ],
      signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])

    XCTAssertTrue(result.errors.isEmpty, "errors: \(result.errors)")
    let messages = result.events.compactMap { event -> Message? in
      guard case .message(let message) = event.event else { return nil }
      return message
    }
    XCTAssertEqual(messages.count, 2)
    XCTAssertEqual(messages[0].text, TestVectors.string("event_reply_text"))
    XCTAssertEqual(messages[0].replyPreviewValidation, .valid)
    XCTAssertEqual(messages[1].replyPreviewValidation, .invalid)
  }

  // MARK: Media

  /// The message's media hash keys, in attachment order, and each file
  /// decrypting under the key derived from the message key and the
  /// attachment's id.
  func testMediaHashesAndAttachmentKeys() throws {
    let keyVersion = TestVectors.string("message_key_conversation_key_version")
    let event = try XChatCore().decryptEvent(
      TestVectors.string("event_message_key_b64"),
      conversationKeys: [
        keyVersion: try Hex.decode(
          TestVectors.string("message_key_conversation_key_hex"))
      ],
      signingKeys: [signingKey(userId: TestVectors.string("message_key_sender_id"))])
    let message = try message(event)

    XCTAssertEqual(
      message.mediaHashes.map(\.mediaHashKey),
      [
        TestVectors.string("media_first_hash_key"),
        TestVectors.string("media_second_hash_key"),
      ])
    XCTAssertEqual(message.mediaHashes.map(\.source), ["media", "media"])

    let messageKey = try deriveMessageKey(
      conversationKey: try Hex.decode(
        TestVectors.string("message_key_conversation_key_hex")),
      senderId: TestVectors.string("message_key_sender_id"),
      messageId: try XCTUnwrap(message.meta.messageId))

    let files: [(hashField: String, encryptedField: String, plaintextField: String)] = [
      ("media_first_hash_key", "media_first_encrypted_b64", "media_first_plaintext_b64"),
      ("media_second_hash_key", "media_second_encrypted_b64", "media_second_plaintext_b64"),
    ]
    for (index, file) in files.enumerated() {
      let hash = TestVectors.string(file.hashField)
      guard
        case .media(let attachment)? = message.attachments.first(where: {
          guard case .media(let media) = $0 else { return false }
          return media.mediaHashKey == hash
        })
      else { return XCTFail("attachment for \(hash) is missing") }

      let attachmentId = resolveAttachmentId(
        storedId: attachment.attachmentId, messageId: message.meta.messageId ?? "",
        index: index)
      let attachmentKey = try deriveAttachmentKey(
        messageKey: messageKey, attachmentId: attachmentId)
      XCTAssertEqual(
        try decryptFile(
          key: attachmentKey,
          ciphertext: TestVectors.bytes(file.encryptedField)),
        TestVectors.bytes(file.plaintextField),
        "\(file.hashField)")
    }
  }

  // MARK: Other variants

  func testTypingEvent() throws {
    let event = MessageEvent(
      senderId: "1111",
      conversationId: "1111:2222",
      detail: .messageTyping(
        MessageTypingEvent(
          conversationId: "1111:2222", activityType: 1, isGrok: false,
          createdAtMilliseconds: "1700000000000")))
    guard case .typing(let typing) = try XChatCore().decryptEvent(encodeEvent(event))
    else {
      return XCTFail("expected a typing event")
    }
    XCTAssertEqual(typing.activityType, 1)
    XCTAssertEqual(typing.meta.senderId, "1111")
  }

  func testFailureEvent() throws {
    let event = try XChatCore().decryptEvent(TestVectors.string("event_failure_b64"))
    guard case .failure(let failure) = event else {
      return XCTFail("expected a failure event")
    }
    XCTAssertNotNil(failure.failureType)
    XCTAssertEqual(failure.meta.messageId, "failure-msg-1")
  }

  /// A read marker (a detail variant this SDK does not model) decrypts to
  /// an unsupported event rather than failing the batch.
  func testUnsupportedDetailEvent() throws {
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
      return XCTFail("expected an unsupported event")
    }
    XCTAssertEqual(unsupported.meta.messageId, "read-msg")
    XCTAssertFalse(unsupported.verified)
  }

  // MARK: Key bindings

  /// A signing key whose identity binding does not verify is dropped, so it
  /// cannot verify events; a valid binding verifies.
  func testSigningKeyBindingFiltering() throws {
    let identityB64 = TestVectors.string("identity_public_b64")
    let identityBytes = TestVectors.bytes("identity_public_b64")
    let signingPrivate = TestVectors.bytes("signing_private_b64")
    let senderId = TestVectors.string("event_sender_id")

    let goodSignature = try sign(privateKey: signingPrivate, payload: identityBytes)
    let boundKey = SigningKeyEntry(
      userId: senderId,
      publicKeyVersion: TestVectors.string("event_signing_key_version"),
      publicKey: TestVectors.string("signing_public_b64"),
      identityPublicKey: identityB64,
      identityPublicKeySignature: Base64.encodeStandard(goodSignature))
    let message = try message(
      XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [boundKey]))
    XCTAssertTrue(message.verified)

    // A binding over the wrong bytes is invalid, so the key is dropped.
    let badSignature = try sign(privateKey: signingPrivate, payload: [1, 2, 3])
    let badKey = SigningKeyEntry(
      userId: senderId,
      publicKeyVersion: TestVectors.string("event_signing_key_version"),
      publicKey: TestVectors.string("signing_public_b64"),
      identityPublicKey: identityB64,
      identityPublicKeySignature: Base64.encodeStandard(badSignature))
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [badKey])
    ) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .verification)
    }
  }
}
