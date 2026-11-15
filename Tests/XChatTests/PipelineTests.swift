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
      return try XCTUnwrap(nil, "expected a message event, got \(event)")
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

  /// The versions keys were given for are listed in numeric order.
  func testMissingConversationKeyThrows() {
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(.missingConversationKey(.message, version: "1001", available: [])))
    }

    let key = [UInt8](repeating: 0, count: 32)
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["10": key, "9": key, "100": key],
        signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .missingConversationKey(.message, version: "1001", available: ["9", "10", "100"])))
    }
  }

  /// A key that does not open the message's contents is named with the
  /// version it was given for, whether it is another key or the wrong
  /// length.
  func testKeyThatDoesNotOpenTheMessageNamesItsVersion() {
    let cases: [([UInt8], XChatError.ContentsFailure)] = [
      ([UInt8](repeating: 1, count: 32), .authenticationFailed),
      ([UInt8](repeating: 1, count: 31), .keyLength(31)),
    ]
    for (key, failure) in cases {
      XCTAssertThrowsError(
        try XChatCore().decryptEvent(
          TestVectors.string("event_message_b64"),
          conversationKeys: ["1001": key],
          signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])
      ) { error in
        XCTAssertEqual(
          error as? XChatError,
          .decryption(
            .messageContents(.message, failure, key: .conversationKey(version: "1001"))))
      }
    }
  }

  /// Contents shorter than a nonce and tag are reported as too short to be
  /// encrypted contents, named with the message and its key's version.
  func testContentsTooShortToBeEncrypted() throws {
    // Replacing the contents breaks the signature, which only the policy
    // would reject.
    let short = try replacingContents(TestVectors.string("event_message_b64"), with: [1, 2, 3])
    XCTAssertThrowsError(
      try XChatCore(rejectUnverified: false).decryptEvent(
        short, conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")])
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(.message, .ciphertextTooShort, key: .conversationKey(version: "1001"))))
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
      XCTAssertEqual(error as? XChatError, .verification(.unverifiable(.message)))
    }

    // With the right key, an event the signed payload cannot be rebuilt
    // from, here for lack of its message id, cannot be checked either.
    let withoutMessageId = try rewritingEvent(TestVectors.string("event_message_b64")) {
      $0.messageId = nil
    }
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        withoutMessageId,
        conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [signingKey(userId: TestVectors.string("event_sender_id"))])
    ) { error in
      XCTAssertEqual(error as? XChatError, .verification(.unverifiable(.message)))
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
      XCTAssertEqual(
        error as? XChatError,
        .parse(.event(.base64(.invalidCharacter(UInt8(ascii: "!"))))))
    }
  }

  // MARK: Errors converted on the way out

  /// Malformed Thrift says what was being read: the event, or the
  /// contents of a message that did decrypt.
  func testMalformedThriftNamesWhatWasRead() throws {
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(Base64.encodeStandard([0x0b, 0x00]))
    ) { error in
      XCTAssertEqual(error as? XChatError, .parse(.event(.thrift(.unexpectedEnd))))
    }

    // Contents that decrypt to a truncated struct, in an unsigned event.
    let key = TestVectors.bytes("conversation_key_b64")
    let event = MessageEvent(
      sequenceId: "1", messageId: "m", senderId: "1111", conversationId: "1111:2222",
      detail: .messageCreate(
        MessageCreateEvent(
          contents: try encryptMessage(key: key, plaintext: [0x0c]),
          conversationKeyVersion: "1001")))
    XCTAssertThrowsError(
      try XChatCore(rejectUnverified: false).decryptEvent(
        encodeEvent(event), conversationKeys: ["1001": key])
    ) { error in
      XCTAssertEqual(error as? XChatError, .parse(.messageContents(.message, .unexpectedEnd)))
    }
  }

  /// An event and a message's contents report what in them is malformed: a
  /// string that is not UTF-8, a list or a map of other types than its
  /// field's, and an attachment of the message or of the message its reply
  /// preview shows that sets none of its variants.
  func testMalformedThriftNamesWhatIsWrong() throws {
    func encoded(_ write: (inout ThriftWriter) -> Void) -> [UInt8] {
      var writer = ThriftWriter()
      write(&writer)
      return writer.data
    }
    // A message-delete event, whose fields are written by `write`.
    func deleteEvent(_ write: (inout ThriftWriter) -> Void) -> String {
      Base64.encodeStandard(
        encoded { writer in
          writer.writeFieldBegin(id: 7, type: .structure)  // detail
          writer.writeFieldBegin(id: 7, type: .structure)  // messageDeleteEvent
          write(&writer)
          writer.writeFieldStop()  // end the delete event
          writer.writeFieldStop()  // end the detail union
          writer.writeFieldStop()  // end the event
        })
    }
    let events: [(name: String, eventB64: String, failure: XChatError.ThriftFailure)] = [
      (
        "message id",
        Base64.encodeStandard(
          encoded {
            $0.writeFieldBegin(id: 2, type: .binary)
            $0.writeBinary([0xFF])
            $0.writeFieldStop()
          }),
        .invalidUTF8
      ),
      (
        "sequence ids",
        deleteEvent {
          $0.writeFieldBegin(id: 1, type: .list)
          $0.writeListBegin(elementType: .i32, count: 0)
        },
        .listElementType(field: "sequence_ids", actual: .i32, expected: .binary)
      ),
      (
        "pinned sequence ids",
        deleteEvent {
          $0.writeFieldBegin(id: 3, type: .map)
          $0.writeMapBegin(keyType: .binary, valueType: .i64, count: 0)
        },
        .mapTypes(field: "pme_sequence_ids", key: .binary, value: .i64)
      ),
    ]
    for (name, eventB64, failure) in events {
      XCTAssertThrowsError(try XChatCore().decryptEvent(eventB64), name) { error in
        XCTAssertEqual(error as? XChatError, .parse(.event(.thrift(failure))), name)
      }
    }

    // An unencrypted message, whose contents are plaintext Thrift: a text
    // message whose fields are written by `write`.
    func message(_ write: (inout ThriftWriter) -> Void) -> String {
      let contents = encoded { writer in
        writer.writeFieldBegin(id: 1, type: .structure)  // contents
        writer.writeFieldBegin(id: 1, type: .structure)  // message
        write(&writer)
        writer.writeFieldStop()  // end the message
        writer.writeFieldStop()  // end the contents union
        writer.writeFieldStop()  // end the holder
      }
      return encodeEvent(
        MessageEvent(
          messageId: "m", senderId: "1111", conversationId: "1111:2222",
          detail: .messageCreate(MessageCreateEvent(contents: contents))))
    }
    let messages: [(name: String, eventB64: String, failure: XChatError.ThriftFailure)] = [
      (
        "text",
        message {
          $0.writeFieldBegin(id: 1, type: .binary)
          $0.writeBinary([0xFF])
        },
        .invalidUTF8
      ),
      (
        "entities",
        message {
          $0.writeFieldBegin(id: 2, type: .list)
          $0.writeListBegin(elementType: .binary, count: 0)
        },
        .listElementType(field: "entities", actual: .binary, expected: .structure)
      ),
      (
        "additional fields",
        message {
          $0.writeFieldBegin(id: 10, type: .map)
          $0.writeMapBegin(keyType: .i32, valueType: .binary, count: 0)
        },
        .mapTypes(field: "additional_fields", key: .i32, value: .binary)
      ),
      (
        "attachment",
        message {
          $0.writeFieldBegin(id: 3, type: .list)
          $0.writeListBegin(elementType: .structure, count: 1)
          $0.writeFieldStop()  // an attachment that sets no variant
        },
        .messageAttachmentWithoutVariant
      ),
      (
        "preview attachment",
        message {
          $0.writeFieldBegin(id: 4, type: .structure)  // replying_to_preview
          $0.writeFieldBegin(id: 4, type: .list)  // attachments
          $0.writeListBegin(elementType: .structure, count: 1)
          $0.writeFieldStop()  // an attachment that sets no variant
          $0.writeFieldStop()  // end the preview
        },
        .previewAttachmentWithoutVariant
      ),
    ]
    for (name, eventB64, failure) in messages {
      XCTAssertThrowsError(
        try XChatCore(rejectUnverified: false).decryptEvent(eventB64), name
      ) { error in
        XCTAssertEqual(error as? XChatError, .parse(.messageContents(.message, failure)), name)
      }
    }
  }

  /// A signature that is checked and fails says why, for a message thrown
  /// by decryptEvent and for a key change collected by decryptEvents.
  func testRejectedSignaturesSayWhy() throws {
    let senderId = TestVectors.string("event_sender_id")
    let keyVersion = TestVectors.string("event_signing_key_version")
    let otherKey = SigningKeyEntry(
      userId: senderId, publicKeyVersion: keyVersion,
      publicKey: Base64.encodeStandard(generateKeyPair().publicKey))
    let notAKey = SigningKeyEntry(
      userId: senderId, publicKeyVersion: keyVersion,
      publicKey: Base64.encodeStandard([0x04] + [UInt8](repeating: 0, count: 64)))
    let keys = ["1001": TestVectors.bytes("conversation_key_b64")]

    let rejections: [(SigningKeyEntry, XChatError.SignatureFailure)] = [
      (otherKey, .mismatch(keyVersion: keyVersion)),
      (notAKey, .invalidSigningPublicKey),
    ]
    for (signingKey, failure) in rejections {
      XCTAssertThrowsError(
        try XChatCore().decryptEvent(
          TestVectors.string("event_message_b64"), conversationKeys: keys,
          signingKeys: [signingKey])
      ) { error in
        XCTAssertEqual(error as? XChatError, .verification(.rejected(.message, failure)))
      }
    }

    var shortSignature = try XChatCore().parseEvent(TestVectors.string("event_message_b64"))
    shortSignature.messageEventSignature?.signature = Base64.encodeStandard([1, 2, 3])
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(
        encodeEvent(shortSignature), conversationKeys: keys,
        signingKeys: [signingKey(userId: senderId)])
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .verification(.rejected(.message, .malformedSignature)))
    }

    let batch = try makeCore().decryptEvents(
      [TestVectors.string("event_key_change_b64")], signingKeys: [notAKey])
    XCTAssertEqual(
      batch.errors, [0: .verification(.rejected(.keyChange, .invalidSigningPublicKey))])
  }

  /// A batch holds only XChatError values; an error of another type would
  /// be kept as its description rather than dropped.
  func testOtherErrorsBecomeUnexpectedWithTheirDescription() {
    struct Other: Error {}
    XCTAssertEqual(XChatError(Other()), .internalError(.unexpected("Other()")))
    XCTAssertEqual(
      XChatError(XChatError.invalidState(.keysNotLoaded)), .invalidState(.keysNotLoaded))
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

    XCTAssertEqual(
      result.errors, [2: .parse(.event(.base64(.invalidCharacter(UInt8(ascii: "!")))))])
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
    XCTAssertEqual(rejected.errors, [0: .verification(.unverifiable(.keyChange))])
    let inspection = try makeCore(rejectUnverified: false)
      .decryptEvents([unsignedEvent], signingKeys: [signing])
    XCTAssertEqual(inspection.events.count, 1)
    XCTAssertTrue(inspection.conversationKeys.keys.isEmpty)

    for keyEvents in [[encoded, unsignedEvent], [unsignedEvent, encoded]] {
      let result = core.decryptEvents(
        keyEvents + [TestVectors.string("event_message_b64")], signingKeys: [signing])
      let unsignedIndex = try XCTUnwrap(keyEvents.firstIndex(of: unsignedEvent))
      XCTAssertEqual(result.errors, [unsignedIndex: .verification(.unverifiable(.keyChange))])
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

    let messageKey = try XCTUnwrap(
      deriveMessageKey(
        conversationKey: try Hex.decode(
          TestVectors.string("message_key_conversation_key_hex")),
        senderId: TestVectors.string("message_key_sender_id"),
        messageId: try XCTUnwrap(message.meta.messageId)))

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
      let attachmentKey = deriveAttachmentKey(
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

  /// An unencrypted message is unverifiable even when its signature holds
  /// under the sender's key: it is rejected by default, and marked
  /// unverified with the policy off.
  func testUnencryptedMessageIsNeverVerified() throws {
    var event = try XChatCore().parseEvent(TestVectors.string("event_unencrypted_b64"))
    let detail = try XCTUnwrap(event.detail)
    let senderId = try XCTUnwrap(event.senderId)
    let keyVersion = TestVectors.string("event_signing_key_version")
    event.messageEventSignature =
      try signEventSignature(
        signingPrivateKey: TestVectors.bytes("signing_private_b64"),
        publicKeyVersion: keyVersion, messageId: try XCTUnwrap(event.messageId),
        senderId: senderId, conversationId: event.conversationId,
        signatureVersion: currentSignatureVersion, detail: detail
      ).signature
    XCTAssertEqual(
      checkEventSignature(
        event: event, detail: detail,
        signingKeys: [
          SigningKey(
            publicKeyVersion: keyVersion, publicKey: TestVectors.string("signing_public_b64"))
        ]),
      .verified)

    let signed = encodeEvent(event)
    XCTAssertThrowsError(
      try XChatCore().decryptEvent(signed, signingKeys: [signingKey(userId: senderId)])
    ) { error in
      XCTAssertEqual(error as? XChatError, .verification(.unverifiable(.message)))
    }
    let message = try message(
      XChatCore(rejectUnverified: false).decryptEvent(
        signed, signingKeys: [signingKey(userId: senderId)]))
    XCTAssertFalse(message.verified)
  }

  /// A signing key whose identity binding does not verify is dropped, so it
  /// cannot verify events; a valid binding verifies.
  func testSigningKeyBindingFiltering() throws {
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
    XCTAssertTrue(message.verified)

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
      // The right signature without the identity key it is checked under.
      SigningKeyEntry(
        userId: senderId,
        publicKeyVersion: TestVectors.string("event_signing_key_version"),
        publicKey: TestVectors.string("signing_public_b64"),
        signingPublicKeySignature: Base64.encodeStandard(goodSignature)),
      // A signature that is not base64.
      SigningKeyEntry(
        userId: senderId,
        publicKeyVersion: TestVectors.string("event_signing_key_version"),
        publicKey: TestVectors.string("signing_public_b64"),
        identityPublicKey: identityB64,
        signingPublicKeySignature: "not base64!"),
    ]
    for key in unauthorized {
      XCTAssertThrowsError(
        try XChatCore().decryptEvent(
          TestVectors.string("event_message_b64"),
          conversationKeys: ["1001": TestVectors.bytes("conversation_key_b64")],
          signingKeys: [key])
      ) { error in
        XCTAssertEqual(error as? XChatError, .verification(.unverifiable(.message)))
      }
    }
  }
}
