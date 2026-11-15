import XCTest

@testable import XChat

/// Files resolved through the message that carries them, files under a
/// caller-held key, and the public-key registration payload.
final class FilesAndKeysTests: XCTestCase {
  private static func messageKeyMap() throws -> [String: [UInt8]] {
    [
      TestVectors.string("message_key_conversation_key_version"): try Hex.decode(
        TestVectors.string("message_key_conversation_key_hex"))
    ]
  }

  // MARK: Received media

  /// Both files of the v1 message decrypt from the event, whole and in
  /// pieces, under keys derived from the message key and attachment ids.
  func testDecryptsVectorMediaFromTheirMessage() throws {
    let core = XChatCore()
    let keys = try Self.messageKeyMap()
    let event = TestVectors.string("event_message_key_b64")

    let files: [(hashField: String, encryptedField: String, plaintextField: String)] = [
      ("media_first_hash_key", "media_first_encrypted_b64", "media_first_plaintext_b64"),
      ("media_second_hash_key", "media_second_encrypted_b64", "media_second_plaintext_b64"),
    ]
    for file in files {
      let hash = TestVectors.string(file.hashField)
      let encrypted = TestVectors.bytes(file.encryptedField)
      let plaintext = TestVectors.bytes(file.plaintextField)

      XCTAssertEqual(
        try core.decryptFile(
          encrypted, eventB64: event, conversationKeys: keys, mediaHashKey: hash),
        plaintext, file.hashField)

      // The incremental decryptor agrees, fed in arbitrary pieces.
      var decryptor = try core.fileDecryptor(
        eventB64: event, conversationKeys: keys, mediaHashKey: hash)
      var pieces: [UInt8] = []
      var offset = 0
      while offset < encrypted.count {
        let end = min(offset + 700, encrypted.count)
        pieces += try decryptor.push(Array(encrypted[offset..<end]))
        offset = end
      }
      pieces += try decryptor.finish()
      XCTAssertEqual(pieces, plaintext, file.hashField)
    }
  }

  /// A link card's banner and favicon share the card's attachment key.
  func testDecryptsLinkCardImages() throws {
    let core = XChatCore()
    let keys = try Self.messageKeyMap()
    let event = TestVectors.string("event_link_card_b64")

    for (hashField, encryptedField, plaintextField) in [
      ("media_banner_hash_key", "media_banner_encrypted_b64", "media_banner_plaintext_b64"),
      ("media_favicon_hash_key", "media_favicon_encrypted_b64", "media_favicon_plaintext_b64"),
    ] {
      XCTAssertEqual(
        try core.decryptFile(
          TestVectors.bytes(encryptedField), eventB64: event,
          conversationKeys: keys,
          mediaHashKey: TestVectors.string(hashField)),
        TestVectors.bytes(plaintextField),
        hashField)
    }
  }

  /// A v0 message's media decrypts under the conversation key.
  func testDecryptsConversationKeyMedia() throws {
    let core = XChatCore()
    let keys = [
      TestVectors.string("event_conversation_key_version"):
        TestVectors.bytes("conversation_key_b64")
    ]
    XCTAssertEqual(
      try core.decryptFile(
        TestVectors.bytes("media_conversation_key_encrypted_b64"),
        eventB64: TestVectors.string("event_conversation_key_media_b64"),
        conversationKeys: keys,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key")),
      TestVectors.bytes("media_conversation_key_plaintext_b64"))
  }

  /// The short-sender message's media resolves its own attachment key.
  func testDecryptsShortMessageMedia() throws {
    let core = XChatCore()
    let keys = [
      TestVectors.string("message_key_short_conversation_key_version"):
        try Hex.decode(TestVectors.string("message_key_short_conversation_key_hex"))
    ]
    XCTAssertEqual(
      try core.decryptFile(
        TestVectors.bytes("media_short_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_short_b64"),
        conversationKeys: keys,
        mediaHashKey: TestVectors.string("media_short_hash_key")),
      TestVectors.bytes("media_short_plaintext_b64"))
  }

  func testUnencryptedEventMediaIsRejected() throws {
    let core = XChatCore()
    XCTAssertThrowsError(
      try core.decryptFile(
        [1, 2, 3],
        eventB64: TestVectors.string("event_unencrypted_b64"),
        conversationKeys: [:],
        mediaHashKey: TestVectors.string("media_unencrypted_hash_key"))
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.notEncrypted(.message)))
    }
  }

  func testUnknownMediaHashNamesTheMessagesHashes() throws {
    let core = XChatCore()
    XCTAssertThrowsError(
      try core.decryptFile(
        [1, 2, 3], eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: try Self.messageKeyMap(), mediaHashKey: "not-a-hash")
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .invalidInput(
          .mediaHashKeyNotFound(
            "not-a-hash",
            available: [
              TestVectors.string("media_first_hash_key"),
              TestVectors.string("media_second_hash_key"),
            ])))
    }
  }

  /// An empty media hash key names no file, on the receiving and the
  /// sending side, and is refused before the message is opened.
  func testEmptyMediaHashKeyIsRefused() throws {
    let core = XChatCore()
    let event = TestVectors.string("event_message_key_b64")
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: event, conversationKeys: try Self.messageKeyMap(), mediaHashKey: "")
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.emptyMediaHashKey))
    }
    XCTAssertThrowsError(
      try core.fileDecryptor(
        eventB64: event, conversationKeys: try Self.messageKeyMap(), mediaHashKey: "")
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.emptyMediaHashKey))
    }
    let (version, key) = try XCTUnwrap(try Self.messageKeyMap().first)
    XCTAssertThrowsError(
      try core.encryptFile(
        [1], eventB64: event, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "")
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.emptyMediaHashKey))
    }
    // FileEncryptor is noncopyable, which XCTAssertThrowsError cannot
    // return.
    do {
      _ = try core.fileEncryptor(
        eventB64: event, conversationKey: key, conversationKeyVersion: version, mediaHashKey: "")
      XCTFail("expected an error")
    } catch {
      XCTAssertEqual(error as? XChatError, .invalidInput(.emptyMediaHashKey))
    }
  }

  /// The versions keys were given for are listed in numeric order.
  func testMissingConversationKeyNamesTheVersion() throws {
    let core = XChatCore()
    let key = [UInt8](repeating: 0, count: 32)
    XCTAssertThrowsError(
      try core.decryptFile(
        TestVectors.bytes("media_first_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: ["10": key, "9": key, "100": key],
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .missingConversationKey(.message, version: "2002", available: ["9", "10", "100"])))
    }
  }

  // MARK: Which message and key an error names

  /// A v1 reply under a new conversation key, quoting `quotedB64`, which is
  /// under `quotedKeys`.
  private func reply(
    quoting quotedB64: String, quotedKeys: [String: [UInt8]]
  ) throws -> (eventB64: String, keys: [String: [UInt8]]) {
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: generateKeyPair().privateKey, publicKeyVersion: "1")
    core.sendVersion = .v1
    let key = [UInt8](repeating: 0xa5, count: 32)
    let payload = try core.encryptReply(
      text: "reply", replyToEventB64: quotedB64,
      conversationId: TestVectors.string("event_conversation_id"),
      conversationKey: key, conversationKeyVersion: "999999",
      senderId: TestVectors.string("event_sender_id"),
      replyToConversationKeys: quotedKeys)
    return (payload.eventB64, ["999999": key])
  }

  /// `reply` with its contents rewritten by `change` and encrypted again
  /// under the reply's own key, derived from `keys`.
  private func rewritingReply(
    _ reply: String, keys: [String: [UInt8]], _ change: (inout MessageContents) -> Void
  ) throws -> String {
    let core = XChatCore()
    var event = try core.parseEvent(reply)
    guard case .messageCreate(var create)? = event.detail,
      let version = create.conversationKeyVersion,
      let conversationKey = keys[version]
    else { return try XCTUnwrap(nil, "expected an encrypted message") }
    let key =
      try core.messageKeyFor(
        event, create: create, conversationKey: conversationKey, role: .message)
      ?? conversationKey
    var reader = ThriftReader(try decryptMessage(key: key, ciphertext: create.contents ?? []))
    var holder = try MessageEntryHolder.read(&reader)
    guard case .message(var contents)? = holder.contents else {
      return try XCTUnwrap(nil, "expected a text message")
    }
    change(&contents)
    holder.contents = .message(contents)
    var writer = ThriftWriter()
    holder.write(to: &writer)
    create.contents = try encryptMessage(key: key, plaintext: writer.data)
    event.detail = .messageCreate(create)
    var eventWriter = ThriftWriter()
    event.write(to: &eventWriter)
    return Base64.encodeStandard(eventWriter.data)
  }

  /// A key that does not open the message's contents is named with the
  /// version it was given for, on the receiving and the sending side; a
  /// key of the wrong length fails as decryption too.
  func testKeyThatDoesNotOpenTheMessageNamesItsVersion() throws {
    let core = XChatCore()
    XCTAssertThrowsError(
      try core.decryptFile(
        TestVectors.bytes("media_first_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: ["2002": [UInt8](repeating: 1, count: 32)],
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .message, .authenticationFailed, key: .conversationKey(version: "2002"))))
    }

    XCTAssertThrowsError(
      try core.decryptFile(
        TestVectors.bytes("media_conversation_key_encrypted_b64"),
        eventB64: TestVectors.string("event_conversation_key_media_b64"),
        conversationKeys: ["1001": [UInt8](repeating: 1, count: 31)],
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(.message, .keyLength(31), key: .conversationKey(version: "1001"))))
    }

    XCTAssertThrowsError(
      try core.encryptFile(
        [1], eventB64: TestVectors.string("event_message_key_b64"),
        conversationKey: [UInt8](repeating: 1, count: 32), conversationKeyVersion: "2002",
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .message, .authenticationFailed, key: .conversationKey(version: "2002"))))
    }
  }

  /// Opening media a reply quotes, a key that does not open the quoted
  /// message is reported for the quoted message: the conversation key given
  /// for its version, or, when none was given, the key the reply carries,
  /// whether it is the wrong key or not 32 bytes.
  func testKeyThatDoesNotOpenTheQuotedMessageNamesIt() throws {
    let core = XChatCore()
    let quotedVersion = TestVectors.string("message_key_conversation_key_version")
    let reply = try reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let encrypted = TestVectors.bytes("media_first_encrypted_b64")
    let mediaHashKey = TestVectors.string("media_first_hash_key")

    var wrongQuotedKey = reply.keys
    wrongQuotedKey[quotedVersion] = [UInt8](repeating: 1, count: 32)
    XCTAssertThrowsError(
      try core.decryptFile(
        encrypted, eventB64: reply.eventB64, conversationKeys: wrongQuotedKey,
        mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .quotedMessage, .authenticationFailed,
            key: .conversationKey(version: quotedVersion))))
    }

    let wrongCarriedKey = try rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageKey = [UInt8](repeating: 1, count: 32)
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        encrypted, eventB64: wrongCarriedKey, conversationKeys: reply.keys,
        mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .quotedMessage, .authenticationFailed,
            key: .carriedByReply(version: quotedVersion))))
    }

    let shortCarriedKey = try rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageKey = [UInt8](repeating: 1, count: 31)
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        encrypted, eventB64: shortCarriedKey, conversationKeys: reply.keys,
        mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .messageContents(
            .quotedMessage, .keyLength(31), key: .carriedByReply(version: quotedVersion))))
    }
  }

  /// A reply carries no key for a quoted v0 message, so without its
  /// conversation key the error names the quoted message and its version.
  func testMissingKeyForTheQuotedMessageNamesIt() throws {
    let reply = try reply(
      quoting: TestVectors.string("event_conversation_key_media_b64"),
      quotedKeys: ["1001": TestVectors.bytes("conversation_key_b64")])
    XCTAssertThrowsError(
      try XChatCore().decryptFile(
        TestVectors.bytes("media_conversation_key_encrypted_b64"),
        eventB64: reply.eventB64, conversationKeys: reply.keys,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .missingConversationKey(.quotedMessage, version: "1001", available: ["999999"])))
    }
  }

  /// A per-message-key message whose event lacks an id its keys derive
  /// from fails with the same case on every path: under its own
  /// conversation key, under the key a reply carries, and quoted in a
  /// reply.
  func testMissingIdsOfAMessageKeyMessageFailAlike() throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let withoutMessageId = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.messageId = nil
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: withoutMessageId, conversationKeys: try Self.messageKeyMap(),
        mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(error as? XChatError, .decryption(.missingSenderOrMessageId(.message)))
    }

    let reply = try reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let carriedWithoutMessageId = try rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate?.messageId = nil
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: carriedWithoutMessageId, conversationKeys: reply.keys,
        mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .decryption(.missingSenderOrMessageId(.quotedMessage)))
    }

    let withoutSenderId = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.senderId = nil
    }
    XCTAssertThrowsError(
      try self.reply(quoting: withoutSenderId, quotedKeys: try Self.messageKeyMap())
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .decryption(.missingSenderOrMessageId(.quotedMessage)))
    }

    let nonNumericSender = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.senderId = "sender-1"
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: nonNumericSender, conversationKeys: try Self.messageKeyMap(),
        mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .decryption(.nonNumericSenderId(.message, "sender-1")))
    }
  }

  /// Opening a reply's media reads the reply's contents and the quoted
  /// message's, so contents that decrypt but do not parse name which one
  /// they are; quoting a message in a reply names it the same way, whether
  /// its contents decrypt or it was sent unencrypted.
  func testMalformedContentsNameTheirMessage() throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let truncatedStruct: [UInt8] = [0x0c]
    let reply = try reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())

    let replyEvent = try core.parseEvent(reply.eventB64)
    let replyVersion = try XCTUnwrap(reply.keys.keys.first)
    let replyKey = try core.messageKey(
      of: replyEvent, conversationKey: try XCTUnwrap(reply.keys[replyVersion]), role: .message)
    let malformedReply = try replacingContents(
      reply.eventB64, with: try encryptMessage(key: replyKey, plaintext: truncatedStruct))
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: malformedReply, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(error as? XChatError, .parse(.messageContents(.message, .unexpectedEnd)))
    }

    let quotedB64 = TestVectors.string("event_message_key_b64")
    let quotedVersion = TestVectors.string("message_key_conversation_key_version")
    let quotedKey = try core.messageKey(
      of: try core.parseEvent(quotedB64),
      conversationKey: try XCTUnwrap(try Self.messageKeyMap()[quotedVersion]),
      role: .quotedMessage)
    let malformedQuotedB64 = try replacingContents(
      quotedB64, with: try encryptMessage(key: quotedKey, plaintext: truncatedStruct))
    let malformedQuoted = try core.parseEvent(malformedQuotedB64)
    // The reply carries the quoted message's key, which opens the
    // replaced contents too: they are under the same sender and message id.
    let quotingMalformed = try rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate = malformedQuoted
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: quotingMalformed, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .parse(.messageContents(.quotedMessage, .unexpectedEnd)))
    }

    XCTAssertThrowsError(
      try self.reply(quoting: malformedQuotedB64, quotedKeys: try Self.messageKeyMap())
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .parse(.messageContents(.quotedMessage, .unexpectedEnd)))
    }

    let malformedUnencryptedB64 = try replacingContents(
      TestVectors.string("event_unencrypted_b64"), with: truncatedStruct)
    XCTAssertThrowsError(try self.reply(quoting: malformedUnencryptedB64, quotedKeys: [:])) {
      error in
      XCTAssertEqual(
        error as? XChatError, .parse(.messageContents(.quotedMessage, .unexpectedEnd)))
    }
  }

  /// Without the quoted message's conversation key, its media opens only
  /// through the quoted event the reply embeds.
  func testQuotedMediaNeedsWhatTheReplyEmbeds() throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let reply = try reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())

    let notEmbedded = try rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate = nil
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: notEmbedded, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.quotedMessageNotEmbedded))
    }
  }

  /// A received reply opens the media of the message it quotes too, so a
  /// media hash key that is in neither lists the quoted message's keys
  /// after the reply's own (here, none).
  func testUnknownMediaHashOfAReplyListsTheQuotedMessagesHashes() throws {
    let core = XChatCore()
    let reply = try reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: reply.eventB64, conversationKeys: reply.keys, mediaHashKey: "nope")
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .invalidInput(
          .mediaHashKeyNotFound(
            "nope",
            available: [
              TestVectors.string("media_first_hash_key"),
              TestVectors.string("media_second_hash_key"),
            ])))
    }
  }

  /// When a received reply's quoted message cannot be opened (here, no key
  /// for its v0 version), an unknown media hash key lists only the reply's
  /// own media: the keys the preview shows are the sender's, unchecked, and
  /// passing one of them reports why the quoted message cannot be opened.
  func testUnknownMediaHashOfAReplyWhoseQuotedMessageDoesNotOpen() throws {
    let core = XChatCore()
    let reply = try reply(
      quoting: TestVectors.string("event_conversation_key_media_b64"),
      quotedKeys: ["1001": TestVectors.bytes("conversation_key_b64")])
    let withOwnMedia = try rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.attachments = [.media(MediaAttachment(mediaHashKey: "own"))]
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: withOwnMedia, conversationKeys: reply.keys, mediaHashKey: "nope")
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .invalidInput(.mediaHashKeyNotFound("nope", available: ["own"])))
    }
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: withOwnMedia, conversationKeys: reply.keys,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(
          .missingConversationKey(.quotedMessage, version: "1001", available: ["999999"])))
    }
  }

  /// Opening media a received reply quotes, an embedded event that cannot
  /// be opened is reported for the quoted message by what is wrong with
  /// it, from `decryptFile` and `fileDecryptor` alike: an event that is not
  /// a message, one from another conversation, an edit, a reaction, and an
  /// unencrypted message.
  func testQuotedEventThatCannotBeOpenedNamesWhy() throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let quotedB64 = TestVectors.string("event_message_key_b64")
    let reply = try reply(quoting: quotedB64, quotedKeys: try Self.messageKeyMap())
    let quoted = try core.parseEvent(quotedB64)
    let quotedKey = try core.messageKey(
      of: quoted,
      conversationKey: try XCTUnwrap(
        try Self.messageKeyMap()[TestVectors.string("message_key_conversation_key_version")]),
      role: .quotedMessage)

    // The quoted event with other contents, under its own message key,
    // which the reply carries.
    func quotedEvent(with contents: MessageEntryContents) throws -> MessageEvent {
      var holder = MessageEntryHolder()
      holder.contents = contents
      var writer = ThriftWriter()
      holder.write(to: &writer)
      return try core.parseEvent(
        try replacingContents(
          quotedB64, with: try encryptMessage(key: quotedKey, plaintext: writer.data)))
    }
    var keyChange = try core.parseEvent(TestVectors.string("event_key_change_b64"))
    keyChange.conversationId = quoted.conversationId
    var otherConversation = quoted
    otherConversation.conversationId = "1:2"
    var unencrypted = quoted
    if case .messageCreate(var create)? = unencrypted.detail {
      create.conversationKeyVersion = nil
      unencrypted.detail = .messageCreate(create)
    }

    let events: [(name: String, event: MessageEvent, failure: XChatError.InputFailure)] = [
      ("key change", keyChange, .notMessageEvent(.quotedMessage)),
      ("other conversation", otherConversation, .quotedMessageInOtherConversation),
      (
        "edit",
        try quotedEvent(
          with: .messageEdit(
            MessageEdit(
              messageSequenceId: "5", updatedText: "edited", entities: nil, messageId: "m"))),
        .messageIsEdit(.quotedMessage)
      ),
      (
        "reaction",
        try quotedEvent(
          with: .reactionAdd(
            MessageReactionAdd(messageSequenceId: "5", emoji: "👍", messageAttachmentId: nil))),
        .notTextMessage(.quotedMessage)
      ),
      ("unencrypted", unencrypted, .notEncrypted(.quotedMessage)),
    ]
    for (name, event, failure) in events {
      let replyB64 = try rewritingReply(reply.eventB64, keys: reply.keys) {
        $0.replyingToPreview?.rawEventMessageCreate = event
      }
      XCTAssertThrowsError(
        try core.decryptFile(
          [], eventB64: replyB64, conversationKeys: reply.keys, mediaHashKey: mediaHashKey),
        name
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(failure), name)
      }
      XCTAssertThrowsError(
        try core.fileDecryptor(
          eventB64: replyB64, conversationKeys: reply.keys, mediaHashKey: mediaHashKey),
        name
      ) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(failure), name)
      }
    }
  }

  /// The four file calls open a message's event, so an event of another
  /// kind is refused as not a message.
  func testFileCallsRefuseAnEventThatIsNotAMessage() throws {
    let core = XChatCore()
    let keyChange = TestVectors.string("event_key_change_b64")
    let (version, key) = try XCTUnwrap(try Self.messageKeyMap().first)
    let expected = XChatError.invalidInput(.notMessageEvent(.message))
    XCTAssertThrowsError(
      try core.decryptFile(
        [], eventB64: keyChange, conversationKeys: [version: key], mediaHashKey: "h")
    ) { error in
      XCTAssertEqual(error as? XChatError, expected)
    }
    XCTAssertThrowsError(
      try core.fileDecryptor(
        eventB64: keyChange, conversationKeys: [version: key], mediaHashKey: "h")
    ) { error in
      XCTAssertEqual(error as? XChatError, expected)
    }
    XCTAssertThrowsError(
      try core.encryptFile(
        [1], eventB64: keyChange, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "h")
    ) { error in
      XCTAssertEqual(error as? XChatError, expected)
    }
    // FileEncryptor is noncopyable, which XCTAssertThrowsError cannot
    // return.
    do {
      _ = try core.fileEncryptor(
        eventB64: keyChange, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "h")
      XCTFail("expected an error")
    } catch {
      XCTAssertEqual(error as? XChatError, expected)
    }
  }

  // MARK: Outgoing files

  func testOutgoingFileRoundTrip() throws {
    let signingPair = generateKeyPair()
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: signingPair.privateKey, publicKeyVersion: "1")
    core.sendVersion = .v1

    let file = (0..<3000).map { UInt8($0 % 251) }
    let mediaHashKey = "file-hash"
    let payload = try core.encryptMessage(
      text: "a file",
      conversationId: "1111:2222",
      conversationKey: TestVectors.bytes("conversation_key_b64"),
      conversationKeyVersion: "1001",
      senderId: "1111",
      attachments: [
        .media(
          mediaHashKey: mediaHashKey, width: 1, height: 1,
          filesizeBytes: Int64(encryptedFileSize(UInt64(file.count)) ?? 0),
          filename: "f.bin", mediaType: 5,
          durationMilliseconds: nil, plaintextSHA256: nil)
      ])
    let keys = ["1001": TestVectors.bytes("conversation_key_b64")]

    let encrypted = try core.encryptFile(
      file, eventB64: payload.eventB64,
      conversationKey: TestVectors.bytes("conversation_key_b64"),
      conversationKeyVersion: "1001", mediaHashKey: mediaHashKey)
    XCTAssertEqual(
      UInt64(encrypted.count), encryptedFileSize(UInt64(file.count)))
    XCTAssertEqual(
      try core.decryptFile(
        encrypted, eventB64: payload.eventB64, conversationKeys: keys,
        mediaHashKey: mediaHashKey),
      file)

    // The incremental encryptor writes the same bytes.
    var encryptor = try core.fileEncryptor(
      eventB64: payload.eventB64,
      conversationKey: TestVectors.bytes("conversation_key_b64"),
      conversationKeyVersion: "1001", mediaHashKey: mediaHashKey)
    var streamed: [UInt8] = []
    var offset = 0
    while offset < file.count {
      let end = min(offset + 700, file.count)
      streamed += try encryptor.push(Array(file[offset..<end]))
      offset = end
    }
    streamed += try encryptor.finish()
    XCTAssertEqual(
      try core.decryptFile(
        streamed, eventB64: payload.eventB64, conversationKeys: keys,
        mediaHashKey: mediaHashKey),
      file)

    // A hash that is not in the message is refused.
    XCTAssertThrowsError(
      try core.encryptFile(
        file, eventB64: payload.eventB64,
        conversationKey: TestVectors.bytes("conversation_key_b64"),
        conversationKeyVersion: "1001", mediaHashKey: "nope")
    ) { error in
      XCTAssertEqual(
        error as? XChatError,
        .invalidInput(.mediaHashKeyNotFound("nope", available: [mediaHashKey])))
    }
  }

  /// An outgoing reply encrypts only its own files: media it quotes was
  /// uploaded with the quoted message, and a reply without files has none
  /// to name.
  func testOutgoingReplyEncryptsOnlyItsOwnFiles() throws {
    let core = XChatCore()
    let reply = try reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let (version, key) = try XCTUnwrap(reply.keys.first)

    let quotedMedia = TestVectors.string("media_first_hash_key")
    XCTAssertThrowsError(
      try core.encryptFile(
        [1], eventB64: reply.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: quotedMedia)
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.quotedMediaHashKey(quotedMedia)))
    }
    XCTAssertThrowsError(
      try core.encryptFile(
        [1], eventB64: reply.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "nope")
    ) { error in
      XCTAssertEqual(
        error as? XChatError, .invalidInput(.mediaHashKeyNotFound("nope", available: [])))
    }
  }

  /// The conversation key and version an outgoing file's key derives from
  /// are the sender's own, so a key of the wrong length or a version not in
  /// canonical form is reported as that parameter, not as the message
  /// failing to open under it or having no key, for a message under the
  /// conversation key itself (v0) or a key derived from it (v1).
  func testOutgoingFileChecksItsOwnKeyAndVersion() throws {
    let core = XChatCore()
    let messages = [
      (
        TestVectors.string("event_conversation_key_media_b64"),
        TestVectors.string("event_conversation_key_version"),
        TestVectors.string("media_conversation_key_hash_key")
      ),
      (
        TestVectors.string("event_message_key_b64"),
        TestVectors.string("message_key_conversation_key_version"),
        TestVectors.string("media_first_hash_key")
      ),
    ]
    for (eventB64, version, mediaHashKey) in messages {
      let parameters: [(key: [UInt8], version: String, failure: XChatError.InputFailure)] = [
        ([UInt8](repeating: 1, count: 31), version, .conversationKeyLength(31)),
        (
          TestVectors.bytes("conversation_key_b64"), "0" + version,
          .conversationKeyVersion("0" + version)
        ),
      ]
      for (key, givenVersion, failure) in parameters {
        XCTAssertThrowsError(
          try core.encryptFile(
            [1], eventB64: eventB64, conversationKey: key,
            conversationKeyVersion: givenVersion, mediaHashKey: mediaHashKey),
          givenVersion
        ) { error in
          XCTAssertEqual(error as? XChatError, .invalidInput(failure), givenVersion)
        }
        // FileEncryptor is noncopyable, which XCTAssertThrowsError cannot
        // return.
        do {
          _ = try core.fileEncryptor(
            eventB64: eventB64, conversationKey: key, conversationKeyVersion: givenVersion,
            mediaHashKey: mediaHashKey)
          XCTFail("expected an error for version \(givenVersion)")
        } catch {
          XCTAssertEqual(error as? XChatError, .invalidInput(failure), givenVersion)
        }
      }
    }
  }

  func testEditEventHasNoMedia() throws {
    let signingPair = generateKeyPair()
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: signingPair.privateKey, publicKeyVersion: "1")
    let payload = try core.encryptEdit(
      targetMessageSequenceId: "5", updatedText: "edited", targetMessageId: "m",
      conversationId: "1111:2222",
      conversationKey: TestVectors.bytes("conversation_key_b64"),
      conversationKeyVersion: "1001", senderId: "1111")

    XCTAssertThrowsError(
      try core.encryptFile(
        [1], eventB64: payload.eventB64,
        conversationKey: TestVectors.bytes("conversation_key_b64"),
        conversationKeyVersion: "1001", mediaHashKey: "h")
    ) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.messageIsEdit(.message)))
    }
  }

  // MARK: Files under a caller-held key

  func testFileWithKeyRoundTrip() throws {
    let core = XChatCore()
    let key = randomBytes(32)
    let file = (0..<2049).map { UInt8($0 % 251) }

    let encrypted = try core.encryptFileWithKey(file, key: key)
    XCTAssertEqual(try core.decryptFileWithKey(encrypted, key: key), file)

    // A wrong key cannot open it: its first frame does not authenticate.
    let otherKey = randomBytes(32)
    XCTAssertThrowsError(try core.decryptFileWithKey(encrypted, key: otherKey)) { error in
      XCTAssertEqual(
        error as? XChatError,
        .decryption(.file(.authenticationFailed, mediaHashKey: nil)))
    }

    for badKey in [[UInt8](repeating: 0, count: 31), [UInt8](repeating: 0, count: 33)] {
      XCTAssertThrowsError(try core.encryptFileWithKey(file, key: badKey)) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(.fileKeyLength(badKey.count)))
      }
      XCTAssertThrowsError(try core.decryptFileWithKey(encrypted, key: badKey)) { error in
        XCTAssertEqual(error as? XChatError, .invalidInput(.fileKeyLength(badKey.count)))
      }
    }
  }

  // MARK: Registration

  func testGenerateKeypairsRegistration() throws {
    let core = XChatCore()
    let payload = try core.generateKeypairs()
    let registration = payload.publicKey

    XCTAssertEqual(registration.registrationMethod, "CustomPin")
    let identitySPKI = try Base64.decodeStandard(registration.publicKey)
    let signingSPKI = try Base64.decodeStandard(registration.signingPublicKey)
    XCTAssertEqual(identitySPKI.count, 91)
    XCTAssertEqual(signingSPKI.count, 91)

    // Both halves of the binding verify.
    XCTAssertTrue(
      try verify(
        publicKey: signingSPKI,  // SPKI is accepted directly
        signature: try Base64.decodeStandard(
          registration.identityPublicKeySignature),
        payload: identitySPKI))
    XCTAssertTrue(
      try verify(
        publicKey: identitySPKI,
        signature: try Base64.decodeStandard(
          try XCTUnwrap(registration.signingPublicKeySignature)),
        payload: signingSPKI))

    // The fingerprint is URL-safe base64 SHA-256 of the identity SPKI.
    XCTAssertEqual(
      registration.publicKeyFingerprint,
      Base64.encodeURLSafe(sha256(identitySPKI)))

    // The loaded keys are the registration's keys in SEC1 form. A receiver
    // checks the binding over the SPKI it rebuilds from the SEC1 signing
    // key (`verifiedSigningKeys`), so that SPKI is the one registered.
    let identitySEC1 = try core.identityPublicKey()
    XCTAssertEqual(try spkiDER(publicKey: identitySEC1), identitySPKI)
    XCTAssertEqual(
      try spkiDER(publicKey: try XCTUnwrap(core.signingPublicKey())), signingSPKI)
    XCTAssertEqual(try core.getPublicKeyFingerprint(), registration.publicKeyFingerprint)
    let publicKeys = try core.getPublicKeys()
    XCTAssertEqual(
      try Base64.decodeStandard(publicKeys.identity), identitySEC1)
    XCTAssertEqual(
      try Base64.decodeStandard(publicKeys.signing),
      try XCTUnwrap(core.signingPublicKey()))

    let exported = try core.exportKeys()
    XCTAssertEqual(exported.identity.count, 32)
    XCTAssertEqual(exported.signing?.count, 32)

    try core.setPublicKeyVersion("123")
    XCTAssertEqual(core.publicKeyVersion, "123")
    XCTAssertThrowsError(try core.setPublicKeyVersion("0123")) { error in
      XCTAssertEqual(error as? XChatError, .invalidInput(.publicKeyVersion("0123")))
    }
  }

  /// The fixture's registration binding: the signing key's signature over
  /// the identity key bytes as the API returns them (SEC1) verifies.
  func testVectorRegistrationBindingVerifies() throws {
    let identity = TestVectors.bytes("identity_public_b64")
    let signature = try Base64.decodeStandard(
      TestVectors.string("identity_public_key_signature_b64"))
    let signingPublic = TestVectors.bytes("signing_public_b64")

    XCTAssertTrue(
      try verify(
        publicKey: signingPublic, signature: signature, payload: identity))
  }
}
