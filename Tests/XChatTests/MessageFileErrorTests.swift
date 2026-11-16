import Testing

@testable import XChat

/// The errors of the file calls that open the message carrying a file
/// (`decryptFile`, `fileDecryptor`, `encryptFile`, `fileEncryptor`): which
/// message and key an error names, a reply's media and the message it
/// quotes, and an outgoing file's own key and version.
struct MessageFileErrorTests {
  /// The key of the per-message-key (v1) vector message, by its version.
  private static func messageKeyMap() throws -> [String: [UInt8]] {
    [
      TestVectors.string("message_key_conversation_key_version"): try Hex.decode(
        TestVectors.string("message_key_conversation_key_hex"))
    ]
  }

  /// A v1 reply under a new conversation key, quoting `quotedB64`, which is
  /// under `quotedKeys`.
  private static func reply(
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
  private static func rewritingReply(
    _ reply: String, keys: [String: [UInt8]], _ change: (inout MessageContents) -> Void
  ) throws -> String {
    let core = XChatCore()
    var event = try core.parseEvent(reply)
    let messageCreate: MessageCreateEvent? =
      switch event.detail {
      case .messageCreate(let create)?: create
      default: nil
      }
    var create = try #require(messageCreate, "expected a message event")
    let version = try #require(create.conversationKeyVersion, "expected an encrypted message")
    let conversationKey = try #require(keys[version], "expected the reply's key")
    let key =
      try core.messageKeyFor(
        event, create: create, conversationKey: conversationKey, role: .message)
      ?? conversationKey
    var reader = ThriftReader(try decryptMessage(key: key, ciphertext: create.contents ?? []))
    var holder = try MessageEntryHolder.read(&reader)
    let text: MessageContents? =
      switch holder.contents {
      case .message(let contents)?: contents
      default: nil
      }
    var contents = try #require(text, "expected a text message")
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

  // MARK: Media hash keys

  /// An empty media hash key names no file, on the receiving and the
  /// sending side, and is refused before the message is opened.
  @Test func emptyMediaHashKeyIsRefused() throws {
    let core = XChatCore()
    let event = TestVectors.string("event_message_key_b64")
    let keys = try Self.messageKeyMap()
    let refused = XChatError.invalidInput(.emptyMediaHashKey)
    #expect(throws: refused, "decryptFile") {
      try core.decryptFile([], eventB64: event, conversationKeys: keys, mediaHashKey: "")
    }
    #expect(throws: refused, "fileDecryptor") {
      try core.fileDecryptor(eventB64: event, conversationKeys: keys, mediaHashKey: "")
    }
    let (version, key) = try #require(keys.first)
    #expect(throws: refused, "encryptFile") {
      try core.encryptFile(
        [1], eventB64: event, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "")
    }
    #expect(throws: refused, "fileEncryptor") {
      _ = try core.fileEncryptor(
        eventB64: event, conversationKey: key, conversationKeyVersion: version, mediaHashKey: "")
    }
  }

  /// A received reply opens the media of the message it quotes too, so a
  /// media hash key that is in neither lists the quoted message's keys
  /// after the reply's own (here, none).
  @Test func unknownMediaHashOfAReplyListsTheQuotedMessagesHashes() throws {
    let reply = try Self.reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    #expect(
      throws: XChatError.invalidInput(
        .mediaHashKeyNotFound(
          "nope",
          available: [
            TestVectors.string("media_first_hash_key"),
            TestVectors.string("media_second_hash_key"),
          ]))
    ) {
      try XChatCore().decryptFile(
        [], eventB64: reply.eventB64, conversationKeys: reply.keys, mediaHashKey: "nope")
    }
  }

  /// When a received reply's quoted message cannot be opened (here, no key
  /// for its v0 version), an unknown media hash key lists only the reply's
  /// own media: the keys the preview shows are the sender's, unchecked, and
  /// passing one of them reports why the quoted message cannot be opened.
  @Test func unknownMediaHashOfAReplyWhoseQuotedMessageDoesNotOpen() throws {
    let core = XChatCore()
    let reply = try Self.reply(
      quoting: TestVectors.string("event_conversation_key_media_b64"),
      quotedKeys: ["1001": TestVectors.bytes("conversation_key_b64")])
    let withOwnMedia = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.attachments = [.media(MediaAttachment(mediaHashKey: "own"))]
    }
    #expect(throws: XChatError.invalidInput(.mediaHashKeyNotFound("nope", available: ["own"]))) {
      try core.decryptFile(
        [], eventB64: withOwnMedia, conversationKeys: reply.keys, mediaHashKey: "nope")
    }
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(.quotedMessage, version: "1001", available: ["999999"]))
    ) {
      try core.decryptFile(
        [], eventB64: withOwnMedia, conversationKeys: reply.keys,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
    }
  }

  // MARK: Which message and key an error names

  /// Without a key for the message's version, the versions keys were given
  /// for are listed in numeric order.
  @Test func missingConversationKeyListsTheVersionsInNumericOrder() throws {
    let key = [UInt8](repeating: 0, count: 32)
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(.message, version: "2002", available: ["9", "10", "100"]))
    ) {
      try XChatCore().decryptFile(
        TestVectors.bytes("media_first_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: ["10": key, "9": key, "100": key],
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    }
  }

  /// A key that does not open the message's contents is named with the
  /// version it was given for, on the receiving and the sending side; a
  /// key of the wrong length fails as decryption too.
  @Test func keyThatDoesNotOpenTheMessageNamesItsVersion() throws {
    let core = XChatCore()
    #expect(
      throws: XChatError.decryption(
        .messageContents(.message, .authenticationFailed, key: .conversationKey(version: "2002"))),
      "decryptFile, v1"
    ) {
      try core.decryptFile(
        TestVectors.bytes("media_first_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: ["2002": [UInt8](repeating: 1, count: 32)],
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    }

    #expect(
      throws: XChatError.decryption(
        .messageContents(.message, .keyLength(31), key: .conversationKey(version: "1001"))),
      "decryptFile, v0"
    ) {
      try core.decryptFile(
        TestVectors.bytes("media_conversation_key_encrypted_b64"),
        eventB64: TestVectors.string("event_conversation_key_media_b64"),
        conversationKeys: ["1001": [UInt8](repeating: 1, count: 31)],
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
    }

    #expect(
      throws: XChatError.decryption(
        .messageContents(.message, .authenticationFailed, key: .conversationKey(version: "2002"))),
      "encryptFile, v1"
    ) {
      try core.encryptFile(
        [1], eventB64: TestVectors.string("event_message_key_b64"),
        conversationKey: [UInt8](repeating: 1, count: 32), conversationKeyVersion: "2002",
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    }
  }

  /// Opening media a reply quotes, a key that does not open the quoted
  /// message is reported for the quoted message: the conversation key given
  /// for its version, or, when none was given, the key the reply carries,
  /// whether it is the wrong key or not 32 bytes.
  @Test func keyThatDoesNotOpenTheQuotedMessageNamesIt() throws {
    let core = XChatCore()
    let quotedVersion = TestVectors.string("message_key_conversation_key_version")
    let reply = try Self.reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let encrypted = TestVectors.bytes("media_first_encrypted_b64")
    let mediaHashKey = TestVectors.string("media_first_hash_key")

    var wrongQuotedKey = reply.keys
    wrongQuotedKey[quotedVersion] = [UInt8](repeating: 1, count: 32)
    #expect(
      throws: XChatError.decryption(
        .messageContents(
          .quotedMessage, .authenticationFailed, key: .conversationKey(version: quotedVersion)))
    ) {
      try core.decryptFile(
        encrypted, eventB64: reply.eventB64, conversationKeys: wrongQuotedKey,
        mediaHashKey: mediaHashKey)
    }

    let wrongCarriedKey = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageKey = [UInt8](repeating: 1, count: 32)
    }
    #expect(
      throws: XChatError.decryption(
        .messageContents(
          .quotedMessage, .authenticationFailed, key: .carriedByReply(version: quotedVersion)))
    ) {
      try core.decryptFile(
        encrypted, eventB64: wrongCarriedKey, conversationKeys: reply.keys,
        mediaHashKey: mediaHashKey)
    }

    let shortCarriedKey = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageKey = [UInt8](repeating: 1, count: 31)
    }
    #expect(
      throws: XChatError.decryption(
        .messageContents(
          .quotedMessage, .keyLength(31), key: .carriedByReply(version: quotedVersion)))
    ) {
      try core.decryptFile(
        encrypted, eventB64: shortCarriedKey, conversationKeys: reply.keys,
        mediaHashKey: mediaHashKey)
    }
  }

  /// A reply carries no key for a quoted v0 message, so without its
  /// conversation key the error names the quoted message and its version.
  @Test func missingKeyForTheQuotedMessageNamesIt() throws {
    let reply = try Self.reply(
      quoting: TestVectors.string("event_conversation_key_media_b64"),
      quotedKeys: ["1001": TestVectors.bytes("conversation_key_b64")])
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(.quotedMessage, version: "1001", available: ["999999"]))
    ) {
      try XChatCore().decryptFile(
        TestVectors.bytes("media_conversation_key_encrypted_b64"),
        eventB64: reply.eventB64, conversationKeys: reply.keys,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
    }
  }

  /// A per-message-key message whose event lacks an id its keys derive
  /// from fails with the same case on every path: under its own
  /// conversation key, under the key a reply carries, and quoted in a
  /// reply. A sender id that is not an integer is its own case.
  @Test func missingIdsOfAMessageKeyMessageFailAlike() throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let withoutMessageId = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.messageId = nil
    }
    #expect(throws: XChatError.decryption(.missingSenderOrMessageId(.message))) {
      try core.decryptFile(
        [], eventB64: withoutMessageId, conversationKeys: try Self.messageKeyMap(),
        mediaHashKey: mediaHashKey)
    }

    let reply = try Self.reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let carriedWithoutMessageId = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate?.messageId = nil
    }
    #expect(throws: XChatError.decryption(.missingSenderOrMessageId(.quotedMessage))) {
      try core.decryptFile(
        [], eventB64: carriedWithoutMessageId, conversationKeys: reply.keys,
        mediaHashKey: mediaHashKey)
    }

    let withoutSenderId = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.senderId = nil
    }
    #expect(throws: XChatError.decryption(.missingSenderOrMessageId(.quotedMessage))) {
      try Self.reply(quoting: withoutSenderId, quotedKeys: try Self.messageKeyMap())
    }

    let nonNumericSender = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.senderId = "sender-1"
    }
    #expect(throws: XChatError.decryption(.nonNumericSenderId(.message, "sender-1"))) {
      try core.decryptFile(
        [], eventB64: nonNumericSender, conversationKeys: try Self.messageKeyMap(),
        mediaHashKey: mediaHashKey)
    }
  }

  /// Opening a reply's media reads the reply's contents and the quoted
  /// message's, so contents that decrypt but do not parse name which one
  /// they are; quoting a message in a reply names it the same way, whether
  /// its contents decrypt or it was sent unencrypted.
  @Test func malformedContentsNameTheirMessage() throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let truncatedStruct: [UInt8] = [0x0c]
    let reply = try Self.reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())

    let replyEvent = try core.parseEvent(reply.eventB64)
    let replyVersion = try #require(reply.keys.keys.first)
    let replyKey = try core.messageKey(
      of: replyEvent, conversationKey: try #require(reply.keys[replyVersion]), role: .message)
    let malformedReply = try replacingContents(
      reply.eventB64, with: try encryptMessage(key: replyKey, plaintext: truncatedStruct))
    #expect(throws: XChatError.parse(.messageContents(.message, .unexpectedEnd)), "the reply") {
      try core.decryptFile(
        [], eventB64: malformedReply, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    }

    let quotedB64 = TestVectors.string("event_message_key_b64")
    let quotedVersion = TestVectors.string("message_key_conversation_key_version")
    let quotedKey = try core.messageKey(
      of: try core.parseEvent(quotedB64),
      conversationKey: try #require(try Self.messageKeyMap()[quotedVersion]),
      role: .quotedMessage)
    let malformedQuotedB64 = try replacingContents(
      quotedB64, with: try encryptMessage(key: quotedKey, plaintext: truncatedStruct))
    let malformedQuoted = try core.parseEvent(malformedQuotedB64)
    // The reply carries the quoted message's key, which opens the
    // replaced contents too: they are under the same sender and message id.
    let quotingMalformed = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate = malformedQuoted
    }
    #expect(
      throws: XChatError.parse(.messageContents(.quotedMessage, .unexpectedEnd)),
      "the quoted message, through the reply"
    ) {
      try core.decryptFile(
        [], eventB64: quotingMalformed, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    }

    #expect(
      throws: XChatError.parse(.messageContents(.quotedMessage, .unexpectedEnd)),
      "the quoted message, encrypted, in encryptReply"
    ) {
      try Self.reply(quoting: malformedQuotedB64, quotedKeys: try Self.messageKeyMap())
    }

    let malformedUnencryptedB64 = try replacingContents(
      TestVectors.string("event_unencrypted_b64"), with: truncatedStruct)
    #expect(
      throws: XChatError.parse(.messageContents(.quotedMessage, .unexpectedEnd)),
      "the quoted message, unencrypted, in encryptReply"
    ) {
      try Self.reply(quoting: malformedUnencryptedB64, quotedKeys: [:])
    }
  }

  // MARK: The message a reply quotes

  /// Without the quoted message's conversation key, its media opens only
  /// through the quoted event the reply embeds.
  @Test func quotedMediaNeedsWhatTheReplyEmbeds() throws {
    let reply = try Self.reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let notEmbedded = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate = nil
    }
    #expect(throws: XChatError.invalidInput(.quotedMessageNotEmbedded)) {
      try XChatCore().decryptFile(
        [], eventB64: notEmbedded, conversationKeys: reply.keys,
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    }
  }

  /// What is wrong with an embedded quoted event that cannot be opened.
  enum UnopenableQuotedEvent: CaseIterable {
    case keyChange
    case otherConversation
    case edit
    case reaction
    case unencrypted

    var failure: XChatError.InputFailure {
      switch self {
      case .keyChange: .notMessageEvent(.quotedMessage)
      case .otherConversation: .quotedMessageInOtherConversation
      case .edit: .messageIsEdit(.quotedMessage)
      case .reaction: .notTextMessage(.quotedMessage)
      case .unencrypted: .notEncrypted(.quotedMessage)
      }
    }
  }

  /// Opening media a received reply quotes, an embedded event that cannot
  /// be opened is reported for the quoted message by what is wrong with
  /// it, from `decryptFile` and `fileDecryptor` alike: an event that is not
  /// a message, one from another conversation, an edit, a reaction, and an
  /// unencrypted message.
  @Test(arguments: UnopenableQuotedEvent.allCases)
  func quotedEventThatCannotBeOpenedNamesWhy(quoted kind: UnopenableQuotedEvent) throws {
    let core = XChatCore()
    let mediaHashKey = TestVectors.string("media_first_hash_key")
    let quotedB64 = TestVectors.string("event_message_key_b64")
    let reply = try Self.reply(quoting: quotedB64, quotedKeys: try Self.messageKeyMap())
    let quoted = try core.parseEvent(quotedB64)
    let quotedKey = try core.messageKey(
      of: quoted,
      conversationKey: try #require(
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
    var event = quoted
    switch kind {
    case .keyChange:
      event = try core.parseEvent(TestVectors.string("event_key_change_b64"))
      event.conversationId = quoted.conversationId
    case .otherConversation:
      event.conversationId = "1:2"
    case .edit:
      let edit = MessageEdit(
        messageSequenceId: "5", updatedText: "edited", entities: nil, messageId: "m")
      event = try quotedEvent(with: .messageEdit(edit))
    case .reaction:
      event = try quotedEvent(
        with: .reactionAdd(
          MessageReactionAdd(messageSequenceId: "5", emoji: "👍", messageAttachmentId: nil)))
    case .unencrypted:
      if case .messageCreate(var create)? = event.detail {
        create.conversationKeyVersion = nil
        event.detail = .messageCreate(create)
      }
    }

    let replyB64 = try Self.rewritingReply(reply.eventB64, keys: reply.keys) {
      $0.replyingToPreview?.rawEventMessageCreate = event
    }
    #expect(throws: XChatError.invalidInput(kind.failure), "decryptFile") {
      try core.decryptFile(
        [], eventB64: replyB64, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    }
    #expect(throws: XChatError.invalidInput(kind.failure), "fileDecryptor") {
      try core.fileDecryptor(
        eventB64: replyB64, conversationKeys: reply.keys, mediaHashKey: mediaHashKey)
    }
  }

  /// The four file calls open a message's event, so an event of another
  /// kind is refused as not a message.
  @Test func fileCallsRefuseAnEventThatIsNotAMessage() throws {
    let core = XChatCore()
    let keyChange = TestVectors.string("event_key_change_b64")
    let (version, key) = try #require(try Self.messageKeyMap().first)
    let refused = XChatError.invalidInput(.notMessageEvent(.message))
    #expect(throws: refused, "decryptFile") {
      try core.decryptFile(
        [], eventB64: keyChange, conversationKeys: [version: key], mediaHashKey: "h")
    }
    #expect(throws: refused, "fileDecryptor") {
      try core.fileDecryptor(
        eventB64: keyChange, conversationKeys: [version: key], mediaHashKey: "h")
    }
    #expect(throws: refused, "encryptFile") {
      try core.encryptFile(
        [1], eventB64: keyChange, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "h")
    }
    #expect(throws: refused, "fileEncryptor") {
      _ = try core.fileEncryptor(
        eventB64: keyChange, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "h")
    }
  }

  // MARK: Outgoing files

  /// An outgoing reply encrypts only its own files: media it quotes was
  /// uploaded with the quoted message, and a reply without files has none
  /// to name.
  @Test func outgoingReplyEncryptsOnlyItsOwnFiles() throws {
    let core = XChatCore()
    let reply = try Self.reply(
      quoting: TestVectors.string("event_message_key_b64"),
      quotedKeys: try Self.messageKeyMap())
    let (version, key) = try #require(reply.keys.first)

    let quotedMedia = TestVectors.string("media_first_hash_key")
    #expect(throws: XChatError.invalidInput(.quotedMediaHashKey(quotedMedia))) {
      try core.encryptFile(
        [1], eventB64: reply.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: quotedMedia)
    }
    #expect(throws: XChatError.invalidInput(.mediaHashKeyNotFound("nope", available: []))) {
      try core.encryptFile(
        [1], eventB64: reply.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "nope")
    }
  }

  /// A message an outgoing file belongs to: under the conversation key
  /// itself (v0) or under a key derived from it (v1).
  enum OutgoingFileMessage: CaseIterable {
    case underConversationKey
    case underMessageKey

    var eventB64: String {
      switch self {
      case .underConversationKey: TestVectors.string("event_conversation_key_media_b64")
      case .underMessageKey: TestVectors.string("event_message_key_b64")
      }
    }

    var conversationKeyVersion: String {
      switch self {
      case .underConversationKey: TestVectors.string("event_conversation_key_version")
      case .underMessageKey: TestVectors.string("message_key_conversation_key_version")
      }
    }

    var mediaHashKey: String {
      switch self {
      case .underConversationKey: TestVectors.string("media_conversation_key_hash_key")
      case .underMessageKey: TestVectors.string("media_first_hash_key")
      }
    }
  }

  /// What is wrong with the key or version an outgoing file's key derives
  /// from.
  enum OwnKeyFault: CaseIterable {
    case keyOf31Bytes
    case versionWithALeadingZero

    /// The key and version to pass for a message sent under `version`, and
    /// the failure they are refused with.
    func arguments(
      forVersion version: String
    ) -> (key: [UInt8], version: String, failure: XChatError.InputFailure) {
      switch self {
      case .keyOf31Bytes:
        ([UInt8](repeating: 1, count: 31), version, .conversationKeyLength(31))
      case .versionWithALeadingZero:
        (
          TestVectors.bytes("conversation_key_b64"), "0" + version,
          .conversationKeyVersion("0" + version)
        )
      }
    }
  }

  /// The conversation key and version an outgoing file's key derives from
  /// are the sender's own, so a key of the wrong length or a version not in
  /// canonical form is reported as that parameter, not as the message
  /// failing to open under it or having no key, for a message under the
  /// conversation key itself (v0) or a key derived from it (v1).
  @Test(arguments: OutgoingFileMessage.allCases, OwnKeyFault.allCases)
  func outgoingFileChecksItsOwnKeyAndVersion(
    message: OutgoingFileMessage, fault: OwnKeyFault
  ) throws {
    let core = XChatCore()
    let (key, version, failure) = fault.arguments(forVersion: message.conversationKeyVersion)
    #expect(throws: XChatError.invalidInput(failure), "encryptFile") {
      try core.encryptFile(
        [1], eventB64: message.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: message.mediaHashKey)
    }
    #expect(throws: XChatError.invalidInput(failure), "fileEncryptor") {
      _ = try core.fileEncryptor(
        eventB64: message.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: message.mediaHashKey)
    }
  }

  /// The sender's own key and version are checked before the media hash
  /// key too, as every send checks them before anything else it is given:
  /// with an empty media hash key as well, the key or version is reported.
  @Test(arguments: OwnKeyFault.allCases)
  func outgoingFileChecksItsOwnKeyBeforeAnEmptyMediaHashKey(fault: OwnKeyFault) {
    let core = XChatCore()
    let message = OutgoingFileMessage.underMessageKey
    let (key, version, failure) = fault.arguments(forVersion: message.conversationKeyVersion)
    #expect(throws: XChatError.invalidInput(failure), "encryptFile") {
      try core.encryptFile(
        [1], eventB64: message.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "")
    }
    #expect(throws: XChatError.invalidInput(failure), "fileEncryptor") {
      _ = try core.fileEncryptor(
        eventB64: message.eventB64, conversationKey: key, conversationKeyVersion: version,
        mediaHashKey: "")
    }
  }
}
