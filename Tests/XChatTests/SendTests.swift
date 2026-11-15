import XCTest

@testable import XChat

/// The send path: message, reply, reaction and edit payloads, and prepared
/// conversation-key changes, checked by decrypting them back with the same
/// rules recipients apply.
final class SendTests: XCTestCase {
  private static let conversationKey = TestVectors.bytes("conversation_key_b64")
  private static let conversationKeyVersion = "1001"
  private static let conversationId = TestVectors.string("event_conversation_id")
  private static let senderId = TestVectors.string("event_sender_id")

  private func fixtureSigningKey() -> SigningKeyEntry {
    SigningKeyEntry(
      userId: Self.senderId,
      publicKeyVersion: TestVectors.string("event_signing_key_version"),
      publicKey: TestVectors.string("signing_public_b64"))
  }

  /// A core with random keys, sending as `version`.
  private func makeCore(
    version: SendVersion = .v0
  ) throws -> (core: XChatCore, signingKey: SigningKeyEntry) {
    let signingPair = generateKeyPair()
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: signingPair.privateKey,
      publicKeyVersion: "1")
    core.sendVersion = version
    return (
      core,
      SigningKeyEntry(
        userId: Self.senderId, publicKeyVersion: "1",
        publicKey: Base64.encodeStandard(signingPair.publicKey))
    )
  }

  private func decrypt(
    _ payload: EncryptedMessagePayload,
    core: XChatCore,
    signingKey: SigningKeyEntry
  ) throws -> Message {
    let event = try core.decryptEvent(
      payload.eventB64,
      conversationKeys: [Self.conversationKeyVersion: Self.conversationKey],
      signingKeys: [signingKey])
    guard case .message(let message) = event else {
      return try XCTUnwrap(nil, "expected a message event, got \(event)")
    }
    return message
  }

  // MARK: Messages

  func testV0MessageRoundTrip() throws {
    let (core, signingKey) = try makeCore()
    let payload = try core.encryptMessage(
      text: "hello",
      conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion,
      senderId: Self.senderId)

    XCTAssertEqual(payload.conversationKeyVersion, Self.conversationKeyVersion)
    XCTAssertTrue(payload.shouldNotify)
    XCTAssertEqual(payload.messageId.count, 36)

    let message = try decrypt(payload, core: core, signingKey: signingKey)
    XCTAssertEqual(message.text, "hello")
    XCTAssertTrue(message.verified)
    XCTAssertEqual(message.meta.messageId, payload.messageId)
    XCTAssertEqual(message.meta.conversationId, Self.conversationId)

    // The encoded MessageCreateEvent is the event's detail.
    let detailBytes = try Base64.decodeStandard(payload.encodedMessageCreateEvent)
    var reader = ThriftReader(detailBytes)
    let createEvent = try MessageCreateEvent.read(&reader)
    XCTAssertNotNil(createEvent.contents)
    XCTAssertNil(createEvent.contentsEncryptionVersion)
    XCTAssertEqual(createEvent.conversationKeyVersion, Self.conversationKeyVersion)

    // The published event signs at version 7.
    var eventReader = ThriftReader(try Base64.decodeStandard(payload.eventB64))
    let event = try MessageEvent.read(&eventReader)
    XCTAssertEqual(event.messageEventSignature?.signatureVersion, "7")
    XCTAssertNil(event.messageEventSignature?.messageSigningKeyInfoList)
  }

  func testV1MessageRoundTripWithEntities() throws {
    let (core, signingKey) = try makeCore(version: .v1)
    let text = "hi @alice"
    let payload = try core.encryptMessage(
      text: text,
      conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion,
      senderId: Self.senderId,
      entities: [
        EntityDescriptor(start: 3, end: 9, type: .mention)
      ],
      shouldNotify: false)

    let message = try decrypt(payload, core: core, signingKey: signingKey)
    XCTAssertEqual(message.text, text)
    XCTAssertTrue(message.verified)
    XCTAssertEqual(message.shouldNotify, false)
    XCTAssertEqual(
      message.content,
      .text(
        TextContent(
          text: text,
          entities: [RichTextEntityInfo(startIndex: 3, endIndex: 9, kind: .mention)],
          attachments: [],
          replyingToPreview: nil,
          forwardedMessage: nil,
          sentFrom: nil,
          quickReply: nil,
          callToActions: nil)))

    // v1 carries contents_encryption_version 1 and signs at v10.
    let detailBytes = try Base64.decodeStandard(payload.encodedMessageCreateEvent)
    var createReader = ThriftReader(detailBytes)
    let createEvent = try MessageCreateEvent.read(&createReader)
    XCTAssertEqual(createEvent.contentsEncryptionVersion, 1)

    var eventReader = ThriftReader(try Base64.decodeStandard(payload.eventB64))
    let event = try MessageEvent.read(&eventReader)
    XCTAssertEqual(event.messageEventSignature?.signatureVersion, "10")
    XCTAssertEqual(
      event.messageEventSignature?.messageSigningKeyInfoList?.count, 1)
    XCTAssertEqual(
      event.messageEventSignature?.messageSigningKeyInfoList?.first?.memberId,
      Self.senderId)
  }

  /// A v1 message with files derives its id from what identifies it, so
  /// building it again keeps the same id and uploaded files valid.
  func testV1MediaMessageIdIsStable() throws {
    let (core, signingKey) = try makeCore(version: .v1)
    let attachments: [AttachmentDescriptor] = [
      .media(
        mediaHashKey: "media-a", width: 10, height: 20, filesizeBytes: 1058,
        filename: "a.jpg", mediaType: 1, durationMilliseconds: nil,
        plaintextSHA256: nil),
      .url(
        url: "https://example.com", displayTitle: "Example",
        bannerImage: UrlAttachmentImageDescriptor(
          mediaHashKey: "banner", filesizeBytes: 1080, filename: "b.png"),
        faviconImage: nil),
    ]

    let first = try core.encryptMessage(
      text: "with files", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
      attachments: attachments)
    let second = try core.encryptMessage(
      text: "with files", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
      attachments: attachments)
    XCTAssertEqual(first.messageId, second.messageId)

    // A different file list gives a different id.
    let third = try core.encryptMessage(
      text: "with files", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
      attachments: [attachments[0]])
    XCTAssertNotEqual(first.messageId, third.messageId)

    // The media hash keys are collected, banner included.
    let message = try decrypt(first, core: core, signingKey: signingKey)
    XCTAssertEqual(
      message.mediaHashes.map(\.mediaHashKey), ["media-a", "banner"])
    XCTAssertEqual(message.mediaHashes.map(\.source), ["media", "url_banner"])
    XCTAssertEqual(
      try XCTUnwrap(message.attachments.first).mediaAttachmentId, first.messageId)
  }

  func testConversationIdIsCanonicalized() throws {
    let (core, signingKey) = try makeCore()
    for conversationId in ["2222:1111", "2222-1111", "2222"] {
      let payload = try core.encryptMessage(
        text: "canonical", conversationId: conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion,
        senderId: Self.senderId)
      let message = try decrypt(payload, core: core, signingKey: signingKey)
      XCTAssertEqual(message.meta.conversationId, "1111:2222", conversationId)
    }
  }

  // MARK: Replies

  func testReplyEmbedsAndValidatesTheOriginal() throws {
    // The fixture's own keys sign for the fixture sender, so the reply
    // and the original verify under one signing key.
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: TestVectors.bytes("identity_private_b64"),
      signingPrivateKey: TestVectors.bytes("signing_private_b64"),
      publicKeyVersion: TestVectors.string("event_recipient_key_version"))
    core.sendVersion = .v1

    let payload = try core.encryptReply(
      text: "a reply",
      replyToEventB64: TestVectors.string("event_message_b64"),
      conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion,
      senderId: Self.senderId)

    let message = try decrypt(payload, core: core, signingKey: fixtureSigningKey())
    XCTAssertEqual(message.text, "a reply")
    XCTAssertTrue(message.verified)
    XCTAssertEqual(message.replyPreviewValidation, .valid)
    guard case .text(let content) = message.content else {
      return XCTFail("expected a text message")
    }
    let preview = try XCTUnwrap(content.replyingToPreview)
    XCTAssertEqual(preview.messageText, TestVectors.string("event_message_text"))
    XCTAssertEqual(preview.senderId, Self.senderId)
    XCTAssertTrue(preview.embedsSourceEvent)
  }

  /// A key that does not open the message a reply quotes is reported for
  /// the quoted message, with the version it was given for: the reply's
  /// own conversation key, or a key in `replyToConversationKeys`.
  func testReplyNamesTheQuotedMessagesKey() throws {
    let (core, _) = try makeCore(version: .v1)
    let wrongKey = [UInt8](repeating: 1, count: 32)

    XCTAssertThrowsError(
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_b64"),
        conversationId: Self.conversationId, conversationKey: wrongKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .quotedMessage, .authenticationFailed,
            key: .conversationKey(version: Self.conversationKeyVersion))))
    }

    let quotedVersion = TestVectors.string("message_key_conversation_key_version")
    XCTAssertThrowsError(
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_key_b64"),
        conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
        replyToConversationKeys: [quotedVersion: wrongKey])
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .quotedMessage, .authenticationFailed,
            key: .conversationKey(version: quotedVersion))))
    }
  }

  /// Without a key for the quoted message's version, a reply lists the
  /// versions it has keys for, its own among them, in numeric order.
  func testReplyListsTheVersionsItHasKeysForInOrder() throws {
    let (core, _) = try makeCore(version: .v1)
    let key = [UInt8](repeating: 1, count: 32)
    XCTAssertThrowsError(
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_key_b64"),
        conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
        replyToConversationKeys: ["10": key, "9": key])
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .missingConversationKey(
            .quotedMessage, version: TestVectors.string("message_key_conversation_key_version"),
            available: ["9", "10", Self.conversationKeyVersion])))
    }
  }

  /// An event that cannot be quoted is reported by what it is, each a case
  /// of its own for the quoted message: a key change, a message event
  /// without contents or a sequence id, an edit, and a reaction.
  func testReplyNamesWhyTheEventCannotBeQuoted() throws {
    let (core, _) = try makeCore()
    // A sent event has no sequence id until the server assigns one.
    func sequenced(_ payload: EncryptedMessagePayload) throws -> String {
      try rewritingEvent(payload.eventB64) { $0.sequenceId = "7" }
    }
    let message = try core.encryptMessage(
      text: "quoted", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    let edit = try core.encryptEdit(
      targetMessageSequenceId: "5", updatedText: "edited", targetMessageId: "m",
      conversationId: Self.conversationId, conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    let reaction = try core.encryptReaction(
      emoji: "👍", targetMessageSequenceId: "5", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)

    let events: [(name: String, eventB64: String, failure: XChatError.InputFailure)] = [
      ("key change", TestVectors.string("event_key_change_b64"), .notMessageEvent(.quotedMessage)),
      (
        "no contents", try replacingContents(TestVectors.string("event_message_b64"), with: nil),
        .noContents(.quotedMessage)
      ),
      ("no sequence id", message.eventB64, .noSequenceId(.quotedMessage)),
      ("edit", try sequenced(edit), .messageIsEdit(.quotedMessage)),
      ("reaction", try sequenced(reaction), .notTextMessage(.quotedMessage)),
    ]
    for (name, eventB64, failure) in events {
      XCTAssertThrowsError(
        try core.encryptReply(
          text: "a reply", replyToEventB64: eventB64, conversationId: Self.conversationId,
          conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId),
        name
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(failure), name)
      }
    }
  }

  /// A reply's own conversation key, version and sender id are reported as
  /// invalid parameters, not as the quoted message failing to open or to
  /// match the reply's conversation, whether the quoted message is under
  /// the conversation key itself (v0) or a key derived from it (v1).
  func testReplyChecksItsOwnParametersBeforeTheQuotedMessage() throws {
    let (core, _) = try makeCore(version: .v1)
    let quoted = [
      (TestVectors.string("event_message_b64"), Self.conversationKeyVersion),
      (
        TestVectors.string("event_message_key_b64"),
        TestVectors.string("message_key_conversation_key_version")
      ),
    ]
    for (eventB64, version) in quoted {
      XCTAssertThrowsError(
        try core.encryptReply(
          text: "a reply", replyToEventB64: eventB64, conversationId: Self.conversationId,
          conversationKey: [UInt8](repeating: 0, count: 31), conversationKeyVersion: version,
          senderId: Self.senderId),
        version
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(.conversationKeyLength(31)), version)
      }
    }

    XCTAssertThrowsError(
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_b64"),
        conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: "0" + Self.conversationKeyVersion, senderId: Self.senderId)
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .invalidInput(.conversationKeyVersion("0" + Self.conversationKeyVersion)))
    }

    // Opened first, the quoted message would not decrypt under this key,
    // and a one-to-one id given as the other user's alone would join the
    // malformed sender id into a conversation the quoted message is not
    // in.
    let otherUser = "2222"
    let senders: [(conversationId: String, key: [UInt8], senderId: String)] = [
      (Self.conversationId, [UInt8](repeating: 1, count: 32), "abc"),
      (otherUser, Self.conversationKey, "0" + Self.senderId),
    ]
    for (conversationId, key, senderId) in senders {
      XCTAssertThrowsError(
        try core.encryptReply(
          text: "a reply", replyToEventB64: TestVectors.string("event_message_b64"),
          conversationId: conversationId, conversationKey: key,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: senderId),
        senderId
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(.senderId(senderId)), senderId)
      }
    }
  }

  // MARK: Reactions and edits

  func testReactionRoundTrips() throws {
    let (core, signingKey) = try makeCore()
    let added = try core.encryptReaction(
      emoji: "👍", targetMessageSequenceId: "5",
      conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    XCTAssertEqual(
      try decrypt(added, core: core, signingKey: signingKey).content,
      .reaction(emoji: "👍", targetMessageSequenceId: "5"))

    let removed = try core.encryptRemoveReaction(
      emoji: "👍", targetMessageSequenceId: "5",
      conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    XCTAssertEqual(
      try decrypt(removed, core: core, signingKey: signingKey).content,
      .reactionRemoved(emoji: "👍", targetMessageSequenceId: "5"))
  }

  func testEditRoundTrip() throws {
    let (core, signingKey) = try makeCore(version: .v1)
    let payload = try core.encryptEdit(
      targetMessageSequenceId: "5",
      updatedText: "new text",
      targetMessageId: "msg-5",
      conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion,
      senderId: Self.senderId,
      entities: [EntityDescriptor(start: 0, end: 3, type: .hashtag)])

    let message = try decrypt(payload, core: core, signingKey: signingKey)
    XCTAssertEqual(
      message.content,
      .edit(
        targetMessageSequenceId: "5", targetMessageId: "msg-5",
        updatedText: "new text",
        entities: [
          RichTextEntityInfo(startIndex: 0, endIndex: 3, kind: .hashtag)
        ]))
  }

  // MARK: Key changes

  func testPreparedKeyChangeRoundTrip() throws {
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: TestVectors.bytes("identity_private_b64"),
      signingPrivateKey: TestVectors.bytes("signing_private_b64"),
      publicKeyVersion: TestVectors.string("event_recipient_key_version"))
    core.sendVersion = .v1

    let other = generateKeyPair()
    let prepared = try core.prepareConversationKeyChange(
      participants: [
        ConversationParticipantPublicKey(
          userId: Self.senderId,
          identityPublicKey: TestVectors.string("identity_public_b64"),
          publicKeyVersion: TestVectors.string("event_recipient_key_version")),
        ConversationParticipantPublicKey(
          userId: "2222",
          identityPublicKey: Base64.encodeStandard(other.publicKey),
          publicKeyVersion: "1"),
      ],
      conversationId: Self.conversationId,
      senderId: Self.senderId,
      conversationKeyVersion: "5000")

    XCTAssertEqual(prepared.conversationId, Self.conversationId)
    XCTAssertEqual(prepared.conversationKey.count, 32)
    XCTAssertEqual(prepared.participantKeys.count, 2)
    XCTAssertEqual(prepared.actionSignature.signature.signatureVersion, "10")

    // Rebuild the event the API persists and decrypt it back: the signed
    // detail and signature verify, and the participant key decrypts for
    // this identity.
    let detailBytes = try Base64.decodeStandard(
      prepared.actionSignature.encodedMessageEventDetail)
    var detailReader = ThriftReader(detailBytes)
    let detail = try XCTUnwrap(MessageEventDetail.read(&detailReader))
    var event = MessageEvent()
    event.messageId = prepared.actionSignature.messageId
    event.senderId = Self.senderId
    event.conversationId = prepared.conversationId
    event.detail = detail
    event.messageEventSignature = MessageEventSignature(
      signature: prepared.actionSignature.signature.signature,
      publicKeyVersion: prepared.actionSignature.signature.publicKeyVersion,
      signatureVersion: prepared.actionSignature.signature.signatureVersion,
      signingPublicKey: prepared.actionSignature.signature.signingPublicKey,
      messageSigningKeyInfoList: nil)
    var writer = ThriftWriter()
    event.write(to: &writer)
    let eventB64 = Base64.encodeStandardPadded(writer.data)

    let decrypted = try core.decryptEvent(eventB64, signingKeys: [fixtureSigningKey()])
    guard case .keyChange(let keyChange) = decrypted else {
      return XCTFail("expected a key change")
    }
    XCTAssertTrue(keyChange.verified)
    XCTAssertEqual(keyChange.conversationKeyVersion, "5000")

    // A batch adopts the key through this identity's ECIES entry.
    let batch = core.decryptEvents([eventB64], signingKeys: [fixtureSigningKey()])
    XCTAssertTrue(batch.errors.isEmpty, "errors: \(batch.errors)")
    XCTAssertEqual(batch.conversationKeys.keys["5000"], prepared.conversationKey)
    XCTAssertEqual(batch.conversationKeys.latestVersion, "5000")
  }

  /// An identity key the conversation key cannot be encrypted to names the
  /// participant it belongs to, whether it is not base64, not a P-256
  /// point, or an SPKI naming another curve.
  func testKeyChangeNamesTheParticipantWithABadKey() throws {
    let (core, _) = try makeCore()
    var otherCurve = try spkiDER(publicKey: generateKeyPair().publicKey)
    // The last arc of the named-curve OID.
    otherCurve[22] = 0x02
    let badKeys = [
      "not base64!",
      Base64.encodeStandard([0x04] + [UInt8](repeating: 0, count: 64)),
      Base64.encodeStandard(otherCurve),
    ]
    for badKey in badKeys {
      XCTAssertThrowsError(
        try core.prepareConversationKeyChange(
          participants: [
            ConversationParticipantPublicKey(
              userId: Self.senderId,
              identityPublicKey: TestVectors.string("identity_public_b64"),
              publicKeyVersion: "1"),
            ConversationParticipantPublicKey(
              userId: "2222", identityPublicKey: badKey, publicKeyVersion: "1"),
          ],
          senderId: Self.senderId, conversationKeyVersion: "5000"),
        badKey
      ) { error in
        XCTAssertEqual(
          error as? XChatError, .invalidInput(.participantIdentityKey(userId: "2222")), badKey)
      }
    }
  }

  /// A key change's participants are checked before any key is made: an
  /// empty list, a user id or key version not in canonical decimal form,
  /// and, without a conversation id, participants that are not two users,
  /// from whom no one-to-one id derives.
  func testKeyChangeValidatesItsParticipants() throws {
    let (core, _) = try makeCore()
    func participant(
      _ userId: String, version: String = "1"
    ) -> ConversationParticipantPublicKey {
      ConversationParticipantPublicKey(
        userId: userId, identityPublicKey: TestVectors.string("identity_public_b64"),
        publicKeyVersion: version)
    }
    typealias Case = (
      name: String, participants: [ConversationParticipantPublicKey],
      failure: XChatError.InputFailure
    )
    let me = participant(Self.senderId)
    let cases: [Case] = [
      ("none", [], .noParticipants),
      ("user id 0", [me, participant("0")], .participantUserId("0")),
      ("user id 01", [me, participant("01")], .participantUserId("01")),
      ("key version 01", [me, participant("2222", version: "01")], .participantKeyVersion("01")),
      ("one user", [me, me], .conversationIdNotDerivable(distinctUsers: 1)),
      (
        "three users", [me, participant("2222"), participant("3333")],
        .conversationIdNotDerivable(distinctUsers: 3)
      ),
    ]
    for (name, participants, failure) in cases {
      XCTAssertThrowsError(
        try core.prepareConversationKeyChange(
          participants: participants, senderId: Self.senderId, conversationKeyVersion: "5000"),
        name
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(failure), name)
      }
    }
  }

  // MARK: Validation

  /// Reactions and edits name the message they target by its sequence id,
  /// and a reaction needs an emoji: either one empty is refused.
  func testReactionAndEditTargetsAreChecked() throws {
    let (core, _) = try makeCore()
    func add(emoji: String, target: String) throws {
      _ = try core.encryptReaction(
        emoji: emoji, targetMessageSequenceId: target, conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    }
    func remove(emoji: String, target: String) throws {
      _ = try core.encryptRemoveReaction(
        emoji: emoji, targetMessageSequenceId: target, conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    }
    let reactions: [(name: String, react: (String, String) throws -> Void)] = [
      ("add", add), ("remove", remove),
    ]
    for (name, react) in reactions {
      XCTAssertThrowsError(try react("👍", ""), name) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(.emptyTargetSequenceId), name)
      }
      XCTAssertThrowsError(try react("", "5"), name) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(.emptyReactionEmoji), name)
      }
    }
    XCTAssertThrowsError(
      try core.encryptEdit(
        targetMessageSequenceId: "", updatedText: "edited", targetMessageId: "m",
        conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.emptyTargetSequenceId))
    }
  }

  func testSendValidation() throws {
    let (core, _) = try makeCore()
    func send(
      key: [UInt8] = Self.conversationKey,
      version: String = Self.conversationKeyVersion,
      entities: [EntityDescriptor]? = nil
    ) throws {
      _ = try core.encryptMessage(
        text: "x", conversationId: Self.conversationId, conversationKey: key,
        conversationKeyVersion: version, senderId: Self.senderId, entities: entities)
    }

    XCTAssertThrowsError(try send(key: [UInt8](repeating: 0, count: 31))) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.conversationKeyLength(31)))
    }
    XCTAssertThrowsError(try send(version: "01")) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.conversationKeyVersion("01")))
    }
    XCTAssertThrowsError(
      try send(entities: [EntityDescriptor(start: 0, end: 5, type: .hashtag)])
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.entityRange(start: 0, end: 5)))
    }

    // Sending needs a signing key and its version.
    let noSigning = XChatCore()
    try noSigning.importKeys(identityPrivateKey: generateKeyPair().privateKey)
    XCTAssertThrowsError(
      try noSigning.encryptMessage(
        text: "x", conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion,
        senderId: Self.senderId)
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidState(.signingKeyNotLoaded))
    }

    // The version is state too: no sending call takes it, and the other
    // bindings report it as invalid_state.
    let noVersion = XChatCore()
    try noVersion.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: generateKeyPair().privateKey)
    XCTAssertThrowsError(
      try noVersion.encryptMessage(
        text: "x", conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion,
        senderId: Self.senderId)
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidState(.signingKeyVersionNotSet))
    }
  }

  /// Each invalid field of an attachment descriptor is its own case, with
  /// the index of the descriptor it is in, and for a URL card's image,
  /// which image it is. Descriptors are checked in order, and each one's
  /// fields in the order they are declared, so the first invalid field is
  /// reported.
  func testEachInvalidAttachmentFieldNamesItsCaseAndIndex() throws {
    let (core, _) = try makeCore()
    func media(
      mediaHashKey: String = "h", width: Int64 = 1, height: Int64 = 1,
      filesizeBytes: Int64 = 1, filename: String = "f", mediaType: Int32? = 1,
      plaintextSHA256: String? = nil
    ) -> AttachmentDescriptor {
      .media(
        mediaHashKey: mediaHashKey, width: width, height: height,
        filesizeBytes: filesizeBytes, filename: filename, mediaType: mediaType,
        durationMilliseconds: nil, plaintextSHA256: plaintextSHA256)
    }
    func image(
      mediaHashKey: String = "i", filesizeBytes: Int64 = 1, filename: String = "i.png",
      width: Int64? = 1, height: Int64? = 1
    ) -> UrlAttachmentImageDescriptor {
      UrlAttachmentImageDescriptor(
        mediaHashKey: mediaHashKey, filesizeBytes: filesizeBytes, filename: filename,
        width: width, height: height)
    }
    func card(
      url: String = "https://example.com", banner: UrlAttachmentImageDescriptor? = image(),
      favicon: UrlAttachmentImageDescriptor? = image()
    ) -> AttachmentDescriptor {
      .url(url: url, displayTitle: nil, bannerImage: banner, faviconImage: favicon)
    }
    let notSHA256 = Base64.encodeStandard([UInt8](repeating: 0, count: 31))
    let imageFaults: [(XChatError.CardImageFailure, UrlAttachmentImageDescriptor)] = [
      (.emptyMediaHashKey, image(mediaHashKey: "")),
      (.nonPositiveFilesize, image(filesizeBytes: 0)),
      (.emptyFilename, image(filename: "")),
      (.negativeWidth, image(width: -1)),
      (.negativeHeight, image(height: -1)),
    ]
    var faults: [(XChatError.AttachmentFailure, AttachmentDescriptor)] = [
      (.emptyMediaHashKey, media(mediaHashKey: "")),
      (.negativeWidth, media(width: -1)),
      (.negativeHeight, media(height: -1)),
      (.nonPositiveFilesize, media(filesizeBytes: 0)),
      (.emptyFilename, media(filename: "")),
      (.unknownMediaType(7), media(mediaType: 7)),
      (.plaintextSHA256, media(plaintextSHA256: "not base64!")),
      (.plaintextSHA256, media(plaintextSHA256: notSHA256)),
      (.emptyURL, card(url: "")),
      (.postWithoutReference, .post(restId: nil, postURL: nil)),
      (.postWithoutReference, .post(restId: "", postURL: "")),
      // The first invalid field is reported.
      (.negativeWidth, media(width: -1, height: -1)),
      (.emptyMediaHashKey, media(mediaHashKey: "", filesizeBytes: 0)),
      (.cardImage(.banner, .emptyFilename), card(banner: image(filename: ""), favicon: nil)),
      (
        .cardImage(.banner, .nonPositiveFilesize),
        card(banner: image(filesizeBytes: 0), favicon: image(mediaHashKey: ""))
      ),
      (.cardImage(.favicon, .negativeHeight), card(banner: nil, favicon: image(height: -1))),
      (.emptyURL, card(url: "", banner: image(mediaHashKey: ""))),
    ]
    for (failure, broken) in imageFaults {
      faults.append((.cardImage(.banner, failure), card(banner: broken)))
      faults.append((.cardImage(.favicon, failure), card(favicon: broken)))
    }
    // Valid descriptors of every kind come before the broken one, so its
    // index is not always 0.
    let valid = [media(), card(), .post(restId: "1", postURL: nil)]

    for (failure, broken) in faults {
      for index in 0...valid.count {
        let attachments = Array(valid.prefix(index)) + [broken, media(mediaHashKey: "")]
        XCTAssertThrowsError(
          try core.encryptMessage(
            text: "x", conversationId: Self.conversationId,
            conversationKey: Self.conversationKey,
            conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
            attachments: attachments),
          "\(failure) at \(index)"
        ) { error in
          XCTAssertEqual(
            error as? XChatError, .invalidInput(.attachment(index: index, failure)),
            "\(failure) at \(index)")
        }
      }
    }

    // The valid descriptors are valid, so the faults above are the ones
    // reported.
    XCTAssertNoThrow(
      try core.encryptMessage(
        text: "x", conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
        attachments: valid))
  }

  /// Every send and key change checks that a signing key and its version
  /// are loaded before anything it is given, so a core that cannot sign
  /// says so whatever else is wrong: here, a 31-byte conversation key, a
  /// reply quoting a message no key was given for, and a key change to a
  /// participant whose identity key is not a key.
  func testSendsAndKeyChangesCheckTheSigningStateFirst() throws {
    let (sender, _) = try makeCore()
    let unopenable = try sender.encryptMessage(
      text: "quoted", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey, conversationKeyVersion: "999",
      senderId: Self.senderId)
    // A sent event has no sequence id until the server assigns one.
    let unopenableB64 = try rewritingEvent(unopenable.eventB64) { $0.sequenceId = "7" }
    let shortKey = [UInt8](repeating: 1, count: 31)

    func calls(_ core: XChatCore) -> [(name: String, call: () throws -> Void)] {
      [
        (
          "message",
          {
            _ = try core.encryptMessage(
              text: "x", conversationId: Self.conversationId, conversationKey: shortKey,
              conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
          }
        ),
        (
          "reply",
          {
            _ = try core.encryptReply(
              text: "x", replyToEventB64: unopenableB64, conversationId: Self.conversationId,
              conversationKey: Self.conversationKey,
              conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
          }
        ),
        (
          "reaction",
          {
            _ = try core.encryptReaction(
              emoji: "👍", targetMessageSequenceId: "5", conversationId: Self.conversationId,
              conversationKey: shortKey, conversationKeyVersion: Self.conversationKeyVersion,
              senderId: Self.senderId)
          }
        ),
        (
          "reaction removal",
          {
            _ = try core.encryptRemoveReaction(
              emoji: "👍", targetMessageSequenceId: "5", conversationId: Self.conversationId,
              conversationKey: shortKey, conversationKeyVersion: Self.conversationKeyVersion,
              senderId: Self.senderId)
          }
        ),
        (
          "edit",
          {
            _ = try core.encryptEdit(
              targetMessageSequenceId: "5", updatedText: "x", targetMessageId: nil,
              conversationId: Self.conversationId, conversationKey: shortKey,
              conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
          }
        ),
        (
          "key change",
          {
            _ = try core.prepareConversationKeyChange(
              participants: [
                ConversationParticipantPublicKey(
                  userId: Self.senderId,
                  identityPublicKey: TestVectors.string("identity_public_b64"),
                  publicKeyVersion: "1"),
                ConversationParticipantPublicKey(
                  userId: "2222", identityPublicKey: "not base64!", publicKeyVersion: "1"),
              ],
              senderId: Self.senderId, conversationKeyVersion: "5000")
          }
        ),
      ]
    }

    let noSigningKey = XChatCore()
    try noSigningKey.importKeys(identityPrivateKey: generateKeyPair().privateKey)
    let noVersion = XChatCore()
    try noVersion.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: generateKeyPair().privateKey)
    let states: [(core: XChatCore, failure: XChatError.StateFailure)] = [
      (noSigningKey, .signingKeyNotLoaded),
      (noVersion, .signingKeyVersionNotSet),
    ]
    for (core, failure) in states {
      for (name, call) in calls(core) {
        XCTAssertThrowsError(try call(), "\(name): \(failure)") { error in
          XCTAssertEqual(error as? XChatError, .invalidState(failure), "\(name): \(failure)")
        }
      }
    }

    // With the signing key and its version loaded, each call reports the
    // other fault.
    let others: [XChatError] = [
      .invalidInput(.conversationKeyLength(31)),
      .decryption(
        .missingConversationKey(
          .quotedMessage, version: "999", available: [Self.conversationKeyVersion])),
      .invalidInput(.conversationKeyLength(31)),
      .invalidInput(.conversationKeyLength(31)),
      .invalidInput(.conversationKeyLength(31)),
      .invalidInput(.participantIdentityKey(userId: "2222")),
    ]
    for ((name, call), other) in zip(calls(sender), others) {
      XCTAssertThrowsError(try call(), name) { error in
        XCTAssertEqual(error as? XChatError, other, name)
      }
    }
  }

  /// Every send checks its conversation key, version and sender id before
  /// anything else it is given, so each reports a malformed one alike
  /// whatever else is wrong: here, an entity out of range, an empty
  /// reaction target, or an empty emoji, each reported once the key,
  /// version and sender id are right.
  func testSendsCheckTheirKeyVersionAndSenderIdFirst() throws {
    let (core, _) = try makeCore()
    let quoted = try core.encryptMessage(
      text: "quoted", conversationId: Self.conversationId,
      conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    // A sent event has no sequence id until the server assigns one.
    let quotedB64 = try rewritingEvent(quoted.eventB64) { $0.sequenceId = "7" }
    let entities = [EntityDescriptor(start: 0, end: 99, type: .hashtag)]
    let outOfRange = XChatError.InputFailure.entityRange(start: 0, end: 99)

    typealias Send = (_ key: [UInt8], _ version: String, _ senderId: String) throws -> Void
    let sends: [(name: String, send: Send, otherFailure: XChatError.InputFailure)] = [
      (
        "message",
        { key, version, senderId in
          _ = try core.encryptMessage(
            text: "x", conversationId: Self.conversationId, conversationKey: key,
            conversationKeyVersion: version, senderId: senderId, entities: entities)
        },
        outOfRange
      ),
      (
        "reply",
        { key, version, senderId in
          _ = try core.encryptReply(
            text: "x", replyToEventB64: quotedB64, conversationId: Self.conversationId,
            conversationKey: key, conversationKeyVersion: version, senderId: senderId,
            entities: entities)
        },
        outOfRange
      ),
      (
        "reaction",
        { key, version, senderId in
          _ = try core.encryptReaction(
            emoji: "👍", targetMessageSequenceId: "", conversationId: Self.conversationId,
            conversationKey: key, conversationKeyVersion: version, senderId: senderId)
        },
        .emptyTargetSequenceId
      ),
      (
        "reaction removal",
        { key, version, senderId in
          _ = try core.encryptRemoveReaction(
            emoji: "", targetMessageSequenceId: "5", conversationId: Self.conversationId,
            conversationKey: key, conversationKeyVersion: version, senderId: senderId)
        },
        .emptyReactionEmoji
      ),
      (
        "edit",
        { key, version, senderId in
          _ = try core.encryptEdit(
            targetMessageSequenceId: "5", updatedText: "x", targetMessageId: nil,
            conversationId: Self.conversationId, conversationKey: key,
            conversationKeyVersion: version, senderId: senderId, entities: entities)
        },
        outOfRange
      ),
    ]
    let malformed:
      [(key: [UInt8], version: String, senderId: String, failure: XChatError.InputFailure)] = [
        (
          [UInt8](repeating: 1, count: 31), Self.conversationKeyVersion, Self.senderId,
          .conversationKeyLength(31)
        ),
        (Self.conversationKey, "01", Self.senderId, .conversationKeyVersion("01")),
        (Self.conversationKey, Self.conversationKeyVersion, "abc", .senderId("abc")),
      ]
    for (name, send, otherFailure) in sends {
      for (key, version, senderId, failure) in malformed {
        XCTAssertThrowsError(try send(key, version, senderId), "\(name): \(failure)") { error in
          XCTAssertEqual(error as? XChatError, .invalidInput(failure), "\(name): \(failure)")
        }
      }
      XCTAssertThrowsError(
        try send(Self.conversationKey, Self.conversationKeyVersion, Self.senderId), name
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(otherFailure), name)
      }
    }
  }
}

extension AttachmentInfo {
  /// The media attachment id, when this is a media attachment.
  var mediaAttachmentId: String? {
    guard case .media(let media) = self else { return nil }
    return media.attachmentId
  }
}
