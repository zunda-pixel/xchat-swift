extension XChatCore {
  // MARK: Files of a message

  /// Encrypts a file for an outgoing message: the message's event names the
  /// file by its media hash key, and the SDK derives the key the file is
  /// encrypted under from the message and the conversation key.
  public func encryptFile(
    _ file: [UInt8],
    eventB64: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    mediaHashKey: String
  ) throws -> [UInt8] {
    let key = try outgoingMediaKey(
      eventB64: eventB64, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, mediaHashKey: mediaHashKey)
    return try XChat.encryptFile(key: key, plaintext: file)
  }

  /// An incremental encryptor for a file too large to hold in memory; the
  /// key is resolved like `encryptFile`.
  public func fileEncryptor(
    eventB64: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    mediaHashKey: String
  ) throws -> FileEncryptor {
    let key = try outgoingMediaKey(
      eventB64: eventB64, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, mediaHashKey: mediaHashKey)
    return try FileEncryptor(key: key)
  }

  /// Decrypts a received media file: the message's event names it by its
  /// media hash key, and the SDK derives the key from the message's
  /// conversation key or per-message key. Of the decryption failures, only
  /// those of the file's bytes (`DecryptionFailure.file`) carry the media
  /// hash key: the others are failures to open the message to resolve the
  /// file's key, and name the message instead. A media hash key the
  /// message does not list is `InputFailure.mediaHashKeyNotFound`, which
  /// carries it too.
  public func decryptFile(
    _ encrypted: [UInt8],
    eventB64: String,
    conversationKeys: [String: [UInt8]],
    mediaHashKey: String
  ) throws -> [UInt8] {
    let key = try mediaKey(
      eventB64: eventB64, conversationKeys: conversationKeys,
      mediaHashKey: mediaHashKey)
    return try XChat.decryptMedia(
      key: key, mediaHashKey: mediaHashKey, encrypted: encrypted)
  }

  /// An incremental decryptor for a received media file; the key is
  /// resolved, and the failures of the file's bytes carry its media hash
  /// key, as in `decryptFile`.
  public func fileDecryptor(
    eventB64: String,
    conversationKeys: [String: [UInt8]],
    mediaHashKey: String
  ) throws -> FileDecryptor {
    let key = try mediaKey(
      eventB64: eventB64, conversationKeys: conversationKeys,
      mediaHashKey: mediaHashKey)
    return try FileDecryptor(key: key, mediaHashKey: mediaHashKey)
  }

  // MARK: Files under a caller-held key

  /// Encrypts a file under a 32-byte key the caller holds, in the file wire
  /// format `encryptedFileSize` describes, with nothing derived from a
  /// message.
  public func encryptFileWithKey(_ file: [UInt8], key: [UInt8]) throws -> [UInt8] {
    try XChat.encryptFile(key: key, plaintext: file)
  }

  /// Decrypts a file encrypted under a key the caller holds, such as a
  /// group's avatar image under its conversation key.
  public func decryptFileWithKey(_ encrypted: [UInt8], key: [UInt8]) throws -> [UInt8] {
    try XChat.decryptFile(key: key, ciphertext: encrypted)
  }

  // MARK: Key resolution

  /// What a message's contents and attachments are encrypted under.
  enum AttachmentKeys {
    case conversation([UInt8])
    case message(key: [UInt8], messageId: String)
  }

  struct OpenedMessage {
    var contents: MessageContents
    var keys: AttachmentKeys
  }

  /// The key of the media file `mediaHashKey` names in a received message.
  func mediaKey(
    eventB64: String,
    conversationKeys: [String: [UInt8]],
    mediaHashKey: String
  ) throws -> [UInt8] {
    guard !mediaHashKey.isEmpty else {
      throw XChatError.invalidInput(.emptyMediaHashKey)
    }
    let event = try parseEvent(eventB64)
    guard case .messageCreate(let create)? = event.detail else {
      throw XChatError.invalidInput(.notMessageEvent(.message))
    }
    let message = try openMessage(
      event, create, conversationKeys: conversationKeys, carriedMessageKey: nil,
      role: .message)
    if let key = attachmentKey(message, mediaHashKey: mediaHashKey) {
      return key
    }

    var available = mediaHashKeys(message.contents.attachments)
    if let preview = message.contents.replyingToPreview {
      do {
        let quoted = try openQuoted(
          event, preview: preview, conversationKeys: conversationKeys)
        if let key = attachmentKey(quoted, mediaHashKey: mediaHashKey) {
          return key
        }
        available += mediaHashKeys(quoted.contents.attachments)
      } catch {
        // When the preview shows this media, why its message cannot be
        // opened is the answer. Otherwise the preview's media hash keys are
        // not listed as available: the sender wrote them, unchecked against
        // a message this call cannot open, and passing one of them throws
        // this error.
        if mediaHashKeys(preview.attachments).contains(mediaHashKey) { throw error }
      }
    }

    throw XChatError.invalidInput(.mediaHashKeyNotFound(mediaHashKey, available: available))
  }

  /// The key a file is encrypted under for an outgoing message: the key of
  /// the message's own attachment. Media a reply quotes belongs to the
  /// quoted message and is never encrypted again.
  func outgoingMediaKey(
    eventB64: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    mediaHashKey: String
  ) throws -> [UInt8] {
    // The key and version are the sender's own, as `encryptMessage` takes
    // them, so they are checked first, before the media hash key, as every
    // send checks them before anything else it is given. Checked only by
    // opening the message, a key of the wrong length would fail as the
    // message's contents not decrypting, and a malformed version as no key
    // being given for the message's version.
    guard conversationKey.count == 32 else {
      throw XChatError.invalidInput(.conversationKeyLength(conversationKey.count))
    }
    guard isKeyVersion(conversationKeyVersion) else {
      throw XChatError.invalidInput(.conversationKeyVersion(conversationKeyVersion))
    }
    guard !mediaHashKey.isEmpty else {
      throw XChatError.invalidInput(.emptyMediaHashKey)
    }
    let event = try parseEvent(eventB64)
    guard case .messageCreate(let create)? = event.detail else {
      throw XChatError.invalidInput(.notMessageEvent(.message))
    }
    let message = try openMessage(
      event, create,
      conversationKeys: [conversationKeyVersion: conversationKey],
      carriedMessageKey: nil, role: .message)
    if let key = attachmentKey(message, mediaHashKey: mediaHashKey) {
      return key
    }

    let quoted = mediaHashKeys(message.contents.replyingToPreview?.attachments)
    if quoted.contains(mediaHashKey) {
      throw XChatError.invalidInput(.quotedMediaHashKey(mediaHashKey))
    }
    let own = mediaHashKeys(message.contents.attachments)
    throw XChatError.invalidInput(.mediaHashKeyNotFound(mediaHashKey, available: own))
  }

  /// Decrypts a message event's contents and reports what its attachments'
  /// keys come from. `role` says which message errors are about.
  func openMessage(
    _ event: MessageEvent,
    _ create: MessageCreateEvent,
    conversationKeys: [String: [UInt8]],
    carriedMessageKey: [UInt8]?,
    role: XChatError.MessageRole
  ) throws -> OpenedMessage {
    guard let version = create.conversationKeyVersion else {
      throw XChatError.invalidInput(.notEncrypted(role))
    }
    let carried =
      usesMessageKey(create.contentsEncryptionVersion.map { Int($0) })
      ? carriedMessageKey : nil

    let keys: AttachmentKeys
    let source: XChatError.ContentsKey
    if let conversationKey = conversationKeys[version] {
      if let messageKey = try messageKeyFor(
        event, create: create, conversationKey: conversationKey, role: role)
      {
        keys = .message(key: messageKey, messageId: try requireMessageId(event, role))
      } else {
        keys = .conversation(conversationKey)
      }
      source = .conversationKey(version: version)
    } else if let carried {
      // A carried key of the wrong length fails to decrypt the contents
      // below, as a conversation key given directly does.
      keys = .message(key: carried, messageId: try requireMessageId(event, role))
      source = .carriedByReply(version: version)
    } else {
      throw XChatError.decryption(
        .missingConversationKey(
          role, version: version, available: keyVersionsInOrder(conversationKeys.keys)))
    }

    guard let contents = create.contents else {
      throw XChatError.invalidInput(.noContents(role))
    }
    let contentsKey: [UInt8]
    switch keys {
    case .conversation(let key): contentsKey = key
    case .message(let key, _): contentsKey = key
    }
    let plaintext = try decryptContents(contents, key: contentsKey, of: role, from: source)
    let holder = try readThrift(
      plaintext, as: { .messageContents(role, $0) }, MessageEntryHolder.read)
    switch holder.contents {
    case .message(let message):
      return OpenedMessage(contents: message, keys: keys)
    case .messageEdit:
      throw XChatError.invalidInput(.messageIsEdit(role))
    default:
      throw XChatError.invalidInput(.notTextMessage(role))
    }
  }

  /// Decrypts the message a reply quotes, embedded in its preview.
  private func openQuoted(
    _ reply: MessageEvent,
    preview: ReplyingToPreview,
    conversationKeys: [String: [UInt8]]
  ) throws -> OpenedMessage {
    guard let quoted = preview.rawEventMessageCreate else {
      throw XChatError.invalidInput(.quotedMessageNotEmbedded)
    }
    guard let conversationId = quoted.conversationId,
      conversationId == reply.conversationId
    else {
      throw XChatError.invalidInput(.quotedMessageInOtherConversation)
    }
    guard case .messageCreate(let create)? = quoted.detail else {
      throw XChatError.invalidInput(.notMessageEvent(.quotedMessage))
    }
    return try openMessage(
      quoted, create, conversationKeys: conversationKeys,
      carriedMessageKey: preview.rawEventMessageKey, role: .quotedMessage)
  }

  /// The key of the attachment carrying `mediaHashKey`, when the message
  /// has one.
  private func attachmentKey(
    _ message: OpenedMessage, mediaHashKey: String
  ) -> [UInt8]? {
    guard
      let found = findAttachment(
        message.contents.attachments, mediaHashKey: mediaHashKey)
    else { return nil }
    switch message.keys {
    case .conversation(let key):
      return key
    case .message(let messageKey, let messageId):
      return deriveAttachmentKey(
        messageKey: messageKey,
        attachmentId: resolveAttachmentId(
          storedId: found.ownId, messageId: messageId, index: found.position))
    }
  }

  /// Finds the attachment carrying `mediaHashKey` and its position; a URL
  /// card's banner and favicon share the card's attachment.
  private func findAttachment(
    _ attachments: [MessageAttachment]?, mediaHashKey: String
  ) -> (position: Int, ownId: String?)? {
    var position = 0
    for attachment in attachments ?? [] {
      switch attachment {
      case .unsupported:
        // Kinds this SDK does not open carry no media; they consume
        // no position, matching the reference's skips.
        continue
      case .media(let media) where media.mediaHashKey == mediaHashKey:
        return (position, media.attachmentId)
      case .url(let card)
      where card.bannerImage?.mediaHashKey == mediaHashKey
        || card.faviconImage?.mediaHashKey == mediaHashKey:
        return (position, card.attachmentId)
      default:
        position += 1
      }
    }
    return nil
  }

  /// The media hash keys of a message's or preview's attachments, in order.
  private func mediaHashKeys(_ attachments: [MessageAttachment]?) -> [String] {
    (attachments ?? []).flatMap { attachment -> [String] in
      switch attachment {
      case .media(let media):
        return media.mediaHashKey.map { [$0] } ?? []
      case .url(let card):
        return [card.bannerImage?.mediaHashKey, card.faviconImage?.mediaHashKey]
          .compactMap { $0 }
      default:
        return []
      }
    }
  }

  /// The message id a per-message key's attachments derive their keys
  /// from; its absence fails like a message key's missing ids.
  private func requireMessageId(
    _ event: MessageEvent, _ role: XChatError.MessageRole
  ) throws -> String {
    guard let messageId = event.messageId else {
      throw XChatError.decryption(.missingSenderOrMessageId(role))
    }
    return messageId
  }
}
