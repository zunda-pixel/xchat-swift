extension XChatCore {
  // MARK: Sending

  /// Encrypts and signs a text message.
  ///
  /// The message id is minted here (a v1 message with files derives it from
  /// what identifies the message, so retries keep their uploaded files
  /// valid). The returned payload is what the API's send request carries.
  public func encryptMessage(
    text: String,
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    entities: [EntityDescriptor]? = nil,
    attachments: [AttachmentDescriptor]? = nil,
    quickReply: QuickReplyInfo? = nil,
    shouldNotify: Bool? = nil,
    ttlMilliseconds: Int64? = nil
  ) throws -> EncryptedMessagePayload {
    let version = sendVersion
    let messageId = try outgoingMessageId(
      version: version, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      conversationId: conversationId, attachments: attachments)
    let content = try buildMessageContent(
      text: text, entities: entities, attachments: attachments,
      quickReply: quickReply, messageId: messageId, version: version,
      replyPreview: nil)
    return try encryptAndSign(
      contentBytes: content, conversationId: conversationId,
      conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      messageId: messageId, version: version, shouldNotify: shouldNotify,
      ttlMilliseconds: ttlMilliseconds, embeddedSigners: [])
  }

  /// Encrypts and signs a reply to a received message.
  ///
  /// The original event (`DecryptedEvent.originalB64` from decryption) is
  /// embedded in the preview so recipients can validate it, and a v1
  /// original's message key travels with it so they can decrypt it.
  public func encryptReply(
    text: String,
    replyToEventB64: String,
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    entities: [EntityDescriptor]? = nil,
    attachments: [AttachmentDescriptor]? = nil,
    quickReply: QuickReplyInfo? = nil,
    shouldNotify: Bool? = nil,
    ttlMilliseconds: Int64? = nil,
    replyToAttachmentId: String? = nil
  ) throws -> EncryptedMessagePayload {
    let version = sendVersion
    let messageId = try outgoingMessageId(
      version: version, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      conversationId: conversationId, attachments: attachments)
    let reply = try buildReplyPreview(
      replyToEventB64: replyToEventB64,
      conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion,
      replyToAttachmentId: replyToAttachmentId)
    let content = try buildMessageContent(
      text: text, entities: entities, attachments: attachments,
      quickReply: quickReply, messageId: messageId, version: version,
      replyPreview: reply.preview)
    return try encryptAndSign(
      contentBytes: content, conversationId: conversationId,
      conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      messageId: messageId, version: version, shouldNotify: shouldNotify,
      ttlMilliseconds: ttlMilliseconds, embeddedSigners: reply.signers)
  }

  /// Encrypts and signs a reaction added to a message.
  public func encryptReaction(
    emoji: String,
    targetMessageSequenceId: String,
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    shouldNotify: Bool? = nil
  ) throws -> EncryptedMessagePayload {
    try encryptContent(
      MessageEntryContents.reactionAdd(
        MessageReactionAdd(
          messageSequenceId: try requireSequenceId(targetMessageSequenceId),
          emoji: try requireEmoji(emoji),
          messageAttachmentId: nil)),
      conversationId: conversationId, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      shouldNotify: shouldNotify, embeddedSigners: [])
  }

  /// Encrypts and signs a reaction removed from a message.
  public func encryptRemoveReaction(
    emoji: String,
    targetMessageSequenceId: String,
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    shouldNotify: Bool? = nil
  ) throws -> EncryptedMessagePayload {
    try encryptContent(
      MessageEntryContents.reactionRemove(
        MessageReactionRemove(
          messageSequenceId: try requireSequenceId(targetMessageSequenceId),
          emoji: try requireEmoji(emoji),
          messageAttachmentId: nil)),
      conversationId: conversationId, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      shouldNotify: shouldNotify, embeddedSigners: [])
  }

  /// Encrypts and signs an edit of a message's text. `targetMessageId` is
  /// the edited message's own id, which names it within the edit's signed
  /// contents.
  public func encryptEdit(
    targetMessageSequenceId: String,
    updatedText: String,
    targetMessageId: String?,
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    entities: [EntityDescriptor]? = nil,
    shouldNotify: Bool? = nil
  ) throws -> EncryptedMessagePayload {
    let thriftEntities = try entities.map {
      try buildThriftEntities($0, text: updatedText)
    }
    return try encryptContent(
      MessageEntryContents.messageEdit(
        MessageEdit(
          messageSequenceId: try requireSequenceId(targetMessageSequenceId),
          updatedText: updatedText,
          entities: thriftEntities,
          messageId: targetMessageId)),
      conversationId: conversationId, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      shouldNotify: shouldNotify, embeddedSigners: [])
  }

  // MARK: Conversation keys

  /// Prepares a signed conversation-key change: a fresh key, each
  /// participant's ECIES-encrypted copy of it, and the signed event the
  /// API persists. `conversationId` may be omitted for a one-to-one, where
  /// it is derived from the two participants.
  public func prepareConversationKeyChange(
    participants: [ConversationParticipantPublicKey],
    conversationId: String? = nil,
    senderId: String,
    conversationKeyVersion: String,
    forKeyRotation: Bool = false
  ) throws -> PreparedConversationChange {
    try validateUserId("sender_id", senderId)
    try validateKeyVersion("conversation_key_version", conversationKeyVersion)
    guard !participants.isEmpty else {
      throw XChatError.invalidInput("public_keys must not be empty")
    }

    // Keep each user's newest key version.
    var best: [String: ConversationParticipantPublicKey] = [:]
    var order: [String] = []
    for participant in participants {
      try validateUserId("public_keys user_id", participant.userId)
      try validateKeyVersion(
        "public_keys public_key_version", participant.publicKeyVersion)
      if let current = best[participant.userId] {
        let newer: Bool
        if let newVersion = UInt64(participant.publicKeyVersion),
          let currentVersion = UInt64(current.publicKeyVersion)
        {
          newer = newVersion > currentVersion
        } else {
          newer = participant.publicKeyVersion > current.publicKeyVersion
        }
        if !newer { continue }
      } else {
        order.append(participant.userId)
      }
      best[participant.userId] = participant
    }

    let resolvedConversationId: String
    if let conversationId, !conversationId.isEmpty {
      resolvedConversationId = canonicalConversationId(conversationId, senderId: senderId)
    } else {
      let distinctIds = Set(participants.map(\.userId))
      guard distinctIds.count == 2 else {
        throw XChatError.invalidInput(
          "cannot derive a one-to-one conversation id from "
            + "\(distinctIds.count) distinct user(s); "
            + "pass conversation_id explicitly for group conversations")
      }
      let ids = order
      resolvedConversationId = joinSortedPair(ids[0], ids[1])
    }

    let conversationKey = randomBytes(32)
    var participantKeys: [ParticipantKey] = []
    for userId in order {
      guard let participant = best[userId] else { continue }
      let publicKey = try Base64.decodeStandard(participant.identityPublicKey)
      let encrypted = try encryptWithPublicKey(publicKey: publicKey, data: conversationKey)
      participantKeys.append(
        ParticipantKey(
          userId: userId,
          encryptedConversationKey: Base64.encodeStandard(encrypted),
          publicKeyVersion: participant.publicKeyVersion))
    }

    let detail = MessageEventDetail.conversationKeyChange(
      ConversationKeyChangeEvent(
        conversationKeyVersion: conversationKeyVersion,
        conversationParticipantKeys: participantKeys.map {
          ConversationParticipantKey(
            userId: $0.userId,
            encryptedConversationKey: $0.encryptedConversationKey,
            publicKeyVersion: $0.publicKeyVersion)
        },
        forKeyRotation: forKeyRotation))

    guard let signingPrivateKey else {
      throw XChatError.invalidState("signing key is not loaded")
    }
    guard let signingKeyVersion = keyVersion else {
      throw XChatError.invalidInput(
        "signing key version is not set: import keys with its public key version")
    }
    let messageId = generateMessageId()
    let signatureVersion = keyChangeSignatureVersion(
      conversationId: resolvedConversationId)
    let (signature, _) = try signEventSignature(
      signingPrivateKey: signingPrivateKey,
      publicKeyVersion: signingKeyVersion,
      messageId: messageId,
      senderId: senderId,
      conversationId: resolvedConversationId,
      signatureVersion: signatureVersion,
      detail: detail,
      plaintextConversationKeyB64: Base64.encodeStandard(conversationKey))
    keyChangeSignatureFloors[resolvedConversationId] = max(
      keyChangeSignatureFloors[resolvedConversationId] ?? 0, signatureVersion)

    var detailWriter = ThriftWriter()
    detail.write(to: &detailWriter)
    return PreparedConversationChange(
      conversationId: resolvedConversationId,
      conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion,
      participantKeys: participantKeys,
      actionSignature: ActionSignatureInfo(
        messageId: messageId,
        encodedMessageEventDetail: Base64.encodeStandardPadded(detailWriter.data),
        signature: MessageEventSignatureSummary(
          signature: signature.signature ?? "",
          publicKeyVersion: signature.publicKeyVersion ?? "",
          signatureVersion: signature.signatureVersion ?? "",
          signingPublicKey: signature.signingPublicKey)))
  }

  // MARK: Internals

  private func encryptContent(
    _ contents: MessageEntryContents,
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    shouldNotify: Bool?,
    embeddedSigners: [(senderId: String, publicKeyVersion: String)]
  ) throws -> EncryptedMessagePayload {
    let messageId = generateMessageId()
    var holder = MessageEntryHolder()
    holder.contents = contents
    var writer = ThriftWriter()
    holder.write(to: &writer)
    return try encryptAndSign(
      contentBytes: writer.data, conversationId: conversationId,
      conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion, senderId: senderId,
      messageId: messageId, version: sendVersion,
      shouldNotify: shouldNotify, ttlMilliseconds: nil,
      embeddedSigners: embeddedSigners)
  }

  private func encryptAndSign(
    contentBytes: [UInt8],
    conversationId: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    messageId: String,
    version: SendVersion,
    shouldNotify: Bool?,
    ttlMilliseconds: Int64?,
    embeddedSigners: [(senderId: String, publicKeyVersion: String)]
  ) throws -> EncryptedMessagePayload {
    guard conversationKey.count == 32 else {
      throw XChatError.invalidInput("Invalid conversation key (expected 32 bytes)")
    }
    try validateUserId("sender_id", senderId)
    try validateKeyVersion("conversation_key_version", conversationKeyVersion)
    guard let signingPrivateKey else {
      throw XChatError.invalidState("signing key is not loaded")
    }
    guard let signingKeyVersion = keyVersion else {
      throw XChatError.invalidInput(
        "signing key version is not set: import keys with its public key version")
    }

    let encrypted: [UInt8]
    let contentsEncryptionVersion: Int16?
    let signatureVersion: Int32
    switch version {
    case .v0:
      encrypted = try XChat.encryptMessage(key: conversationKey, plaintext: contentBytes)
      contentsEncryptionVersion = nil
      signatureVersion = currentSignatureVersion
    case .v1:
      let messageKey = try deriveMessageKey(
        conversationKey: conversationKey, senderId: senderId, messageId: messageId)
      encrypted = try XChat.encryptMessage(key: messageKey, plaintext: contentBytes)
      contentsEncryptionVersion = Int16(sendContentsEncryptionVersion)
      signatureVersion = messageSignatureVersion
    }

    let notify = shouldNotify ?? true
    let createEvent = MessageCreateEvent(
      contents: encrypted,
      conversationKeyVersion: conversationKeyVersion,
      shouldNotify: notify,
      ttlMilliseconds: ttlMilliseconds,
      deliveredAtMilliseconds: nil,
      isPendingPublicKey: nil,
      isMessageRequest: nil,
      contentsEncryptionVersion: contentsEncryptionVersion)
    var createWriter = ThriftWriter()
    createEvent.write(to: &createWriter)

    // The conversation id is signed in its canonical, colon-separated
    // form, the one fanned-out events carry.
    let canonicalId = canonicalConversationId(conversationId, senderId: senderId)
    let detail = MessageEventDetail.messageCreate(createEvent)

    var outgoing = MessageEvent()
    outgoing.messageId = messageId
    outgoing.senderId = senderId
    outgoing.conversationId = canonicalId
    var placeholder = MessageEventSignature()
    placeholder.signatureVersion = String(signatureVersion)
    outgoing.messageEventSignature = placeholder

    guard let payload = eventSignaturePayload(event: outgoing, detail: detail) else {
      throw XChatError.invalidInput(
        "Signature payload contains comma-separated component")
    }
    let signature = try sign(privateKey: signingPrivateKey, payload: Array(payload.utf8))

    // v1 signatures name every signer whose key a recipient needs; v0
    // signatures carry none.
    var signers = embeddedSigners
    if !signers.contains(where: {
      $0.senderId == senderId && $0.publicKeyVersion == signingKeyVersion
    }) {
      signers.append((senderId, signingKeyVersion))
    }
    let signingInfos: [MessageSigningKeyInfo]? =
      version == .v1
      ? signers.map {
        MessageSigningKeyInfo(
          memberId: $0.senderId, publicKeyVersion: $0.publicKeyVersion,
          signingPublicKey: nil)
      }
      : nil

    let signatureStruct = MessageEventSignature(
      signature: Base64.encodeStandard(signature),
      publicKeyVersion: signingKeyVersion,
      signatureVersion: String(signatureVersion),
      signingPublicKey: nil,
      messageSigningKeyInfoList: signingInfos)
    var signatureWriter = ThriftWriter()
    signatureStruct.write(to: &signatureWriter)

    outgoing.detail = detail
    outgoing.messageEventSignature = signatureStruct
    var eventWriter = ThriftWriter()
    outgoing.write(to: &eventWriter)

    return EncryptedMessagePayload(
      messageId: messageId,
      eventB64: Base64.encodeStandardPadded(eventWriter.data),
      encodedMessageCreateEvent: Base64.encodeStandardPadded(createWriter.data),
      signature: signatureStruct.signature ?? "",
      encodedMessageEventSignature: Base64.encodeStandardPadded(signatureWriter.data),
      conversationKeyVersion: conversationKeyVersion,
      shouldNotify: notify)
  }

  /// The message id for an outgoing send: a v1 message with files derives
  /// it from what identifies the message; everything else takes a random
  /// id.
  private func outgoingMessageId(
    version: SendVersion,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    conversationId: String,
    attachments: [AttachmentDescriptor]?
  ) throws -> String {
    let mediaHashKeys = fileMediaHashKeys(attachments ?? [])
    if version == .v0 || mediaHashKeys.isEmpty {
      return generateMessageId()
    }
    let canonicalId = canonicalConversationId(conversationId, senderId: senderId)
    return try deriveMediaMessageId(
      conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion,
      senderId: senderId, conversationId: canonicalId,
      mediaHashKeys: mediaHashKeys)
  }

  /// The media hash keys the descriptors reference, in order: a media
  /// attachment's, and a URL card's banner then favicon.
  private func fileMediaHashKeys(_ attachments: [AttachmentDescriptor]) -> [String] {
    attachments.flatMap { attachment -> [String] in
      switch attachment {
      case .media(let mediaHashKey, _, _, _, _, _, _, _):
        return [mediaHashKey]
      case .url(_, _, let banner, let favicon):
        return [banner?.mediaHashKey, favicon?.mediaHashKey].compactMap { $0 }
      case .post:
        return []
      }
    }
  }

  private func buildMessageContent(
    text: String,
    entities: [EntityDescriptor]?,
    attachments: [AttachmentDescriptor]?,
    quickReply: QuickReplyInfo?,
    messageId: String,
    version: SendVersion,
    replyPreview: ReplyingToPreview?
  ) throws -> [UInt8] {
    let thriftEntities = try entities.map { try buildThriftEntities($0, text: text) }
    let thriftAttachments = try attachments.map {
      try buildThriftAttachments($0, messageId: messageId, version: version)
    }
    let contents = MessageContents(
      messageText: text,
      entities: thriftEntities,
      attachments: thriftAttachments,
      replyingToPreview: replyPreview,
      forwardedMessage: nil,
      sentFrom: nil,
      quickReply: quickReply.map(buildThriftQuickReply),
      callToActions: nil,
      additionalFields: nil)
    var holder = MessageEntryHolder()
    holder.contents = .message(contents)
    var writer = ThriftWriter()
    holder.write(to: &writer)
    return writer.data
  }

  private func buildThriftEntities(
    _ entities: [EntityDescriptor], text: String
  ) throws -> [RichTextEntity] {
    let textByteCount = text.utf8.count
    return try entities.map { entity in
      guard entity.start >= 0, entity.end >= entity.start,
        Int(entity.end) <= textByteCount
      else {
        throw XChatError.invalidInput(
          "Invalid entity: offsets \(entity.start)..<\(entity.end) are not a range "
            + "of the text")
      }
      let content: RichTextContent
      switch entity.type {
      case .hashtag: content = .hashtag
      case .cashtag: content = .cashtag
      case .mention: content = .mention
      case .url: content = .url
      case .email: content = .email
      case .address: content = .address
      case .phoneNumber: content = .phoneNumber
      }
      return RichTextEntity(
        startIndex: entity.start, endIndex: entity.end, content: content)
    }
  }

  private func buildThriftAttachments(
    _ descriptors: [AttachmentDescriptor],
    messageId: String,
    version: SendVersion
  ) throws -> [MessageAttachment] {
    try descriptors.enumerated().map { index, descriptor in
      let attachmentId: String? =
        version == .v1
        ? resolveAttachmentId(storedId: nil, messageId: messageId, index: index)
        : nil
      switch descriptor {
      case .media(
        let mediaHashKey, let width, let height, let filesizeBytes,
        let filename, let mediaType, let durationMilliseconds,
        let plaintextSHA256):
        guard !mediaHashKey.isEmpty else {
          throw XChatError.invalidInput(
            "Invalid attachments[\(index)].media_hash_key: must not be empty")
        }
        guard width >= 0, height >= 0 else {
          throw XChatError.invalidInput(
            "Invalid attachments[\(index)]: width and height must not be negative")
        }
        guard filesizeBytes > 0 else {
          throw XChatError.invalidInput(
            "Invalid attachments[\(index)].filesize_bytes: must be positive")
        }
        guard !filename.isEmpty else {
          throw XChatError.invalidInput(
            "Invalid attachments[\(index)].filename: must not be empty")
        }
        var mediaTypeValue: MediaType?
        if let mediaType {
          guard let parsed = MediaType(rawValue: mediaType) else {
            throw XChatError.invalidInput(
              "Invalid attachments[\(index)].media_type: \(mediaType) is not a "
                + "media type")
          }
          mediaTypeValue = parsed
        }
        var plaintextHash: [UInt8]?
        if let plaintextSHA256, !plaintextSHA256.isEmpty {
          guard
            let decoded = try? Base64.decodeStandard(plaintextSHA256),
            decoded.count == 32
          else {
            throw XChatError.invalidInput(
              "Invalid attachments[\(index)].plaintext_sha256: pass the base64 "
                + "SHA-256 of the file's plaintext bytes")
          }
          plaintextHash = decoded
        }
        return .media(
          MediaAttachment(
            mediaHashKey: mediaHashKey,
            dimensions: MediaDimensions(width: width, height: height),
            type: mediaTypeValue,
            durationMilliseconds: durationMilliseconds,
            filesizeBytes: filesizeBytes,
            filename: filename,
            attachmentId: attachmentId,
            legacyMediaURLHTTPS: nil,
            legacyMediaPreviewURL: nil,
            grokTag: nil,
            plaintextSHA256: plaintextHash))

      case .url(let url, let displayTitle, let bannerImage, let faviconImage):
        guard !url.isEmpty else {
          throw XChatError.invalidInput(
            "Invalid attachments[\(index)].url: must not be empty")
        }
        return .url(
          UrlAttachment(
            url: url,
            bannerImage: try bannerImage.map {
              try buildUrlImage($0, index: index)
            },
            faviconImage: try faviconImage.map {
              try buildUrlImage($0, index: index)
            },
            displayTitle: displayTitle,
            attachmentId: attachmentId))

      case .post(let restId, let postURL):
        guard restId?.isEmpty == false || postURL?.isEmpty == false else {
          throw XChatError.invalidInput(
            "Invalid attachments[\(index)]: a post needs rest_id, post_url, or both")
        }
        return .post(
          PostAttachment(
            restId: restId, postURL: postURL, attachmentId: attachmentId))
      }
    }
  }

  private func buildUrlImage(
    _ image: UrlAttachmentImageDescriptor, index: Int
  ) throws -> UrlAttachmentImage {
    guard !image.mediaHashKey.isEmpty else {
      throw XChatError.invalidInput(
        "Invalid attachments[\(index)] image media_hash_key: must not be empty")
    }
    guard image.filesizeBytes > 0 else {
      throw XChatError.invalidInput(
        "Invalid attachments[\(index)] image filesize_bytes: must be positive")
    }
    guard !image.filename.isEmpty else {
      throw XChatError.invalidInput(
        "Invalid attachments[\(index)] image filename: must not be empty")
    }
    if let width = image.width, width < 0 {
      throw XChatError.invalidInput(
        "Invalid attachments[\(index)] image width: must not be negative")
    }
    if let height = image.height, height < 0 {
      throw XChatError.invalidInput(
        "Invalid attachments[\(index)] image height: must not be negative")
    }
    let dimensions: MediaDimensions? =
      image.width != nil || image.height != nil
      ? MediaDimensions(width: image.width, height: image.height)
      : nil
    return UrlAttachmentImage(
      mediaHashKey: image.mediaHashKey, filesizeBytes: image.filesizeBytes,
      filename: image.filename, dimensions: dimensions)
  }

  private func buildThriftQuickReply(_ quickReply: QuickReplyInfo) -> QuickReply {
    switch quickReply.content {
    case .request(let id, let options):
      return .request(
        QuickReplyRequest(
          options: QuickReplyOptionsRequest(
            id: id,
            options: options.map {
              QuickReplyOption(
                id: $0.id, label: $0.label, metadata: $0.metadata,
                optionDescription: $0.optionDescription)
            })))
    case .response(let requestId, let metadata, let selectedOptionId):
      return .response(
        QuickReplyResponse(
          options: QuickReplyOptionsResponse(
            requestId: requestId, metadata: metadata,
            selectedOptionId: selectedOptionId)))
    }
  }

  /// Builds the reply preview for an outgoing reply, deriving it from the
  /// received original and embedding the original (and a message-key
  /// original's key) so recipients can validate it.
  private func buildReplyPreview(
    replyToEventB64: String,
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    replyToAttachmentId: String?
  ) throws -> (
    preview: ReplyingToPreview, signers: [(senderId: String, publicKeyVersion: String)]
  ) {
    let raw = try parseEvent(replyToEventB64)
    guard case .messageCreate(let create)? = raw.detail, let contents = create.contents else {
      throw XChatError.invalidInput("the reply target is not a message event")
    }
    guard let sequenceId = raw.sequenceId else {
      throw XChatError.invalidInput("the reply target event carries no sequence_id")
    }
    let key = try quotedContentsKey(
      raw, conversationKey: conversationKey,
      conversationKeyVersion: conversationKeyVersion)
    let plaintext: [UInt8]
    if let key {
      plaintext = try decryptMessage(key: key, ciphertext: contents)
    } else {
      plaintext = contents
    }
    var reader = ThriftReader(plaintext)
    let holder: MessageEntryHolder
    do {
      holder = try MessageEntryHolder.read(&reader)
    } catch {
      throw XChatError.parse(
        "Content parse error: \((error as? XChatError)?.message ?? String(describing: error))")
    }
    guard case .message(let original)? = holder.contents else {
      throw XChatError.invalidInput("the reply target is not a text message")
    }

    var preview = ReplyingToPreview()
    preview.senderId = raw.senderId.flatMap { Int64($0) }
    preview.messageText = original.messageText
    preview.entities = original.entities
    preview.attachments = original.attachments
    preview.messageSequenceId = sequenceId
    preview.messageId = raw.messageId
    preview.attachmentId = replyToAttachmentId
    preview.rawEventMessageCreate = raw
    if usesMessageKey(raw) {
      preview.rawEventMessageKey = key
    }

    var signers: [(senderId: String, publicKeyVersion: String)] = []
    if let senderId = raw.senderId,
      let publicKeyVersion = raw.messageEventSignature?.publicKeyVersion
    {
      signers.append((senderId, publicKeyVersion))
    }
    return (preview, signers)
  }

  /// The key a quoted message's contents use: its conversation key when
  /// the versions match, or a key derived from it when the message uses a
  /// per-message key; nil for an unencrypted original.
  private func quotedContentsKey(
    _ raw: MessageEvent,
    conversationKey: [UInt8],
    conversationKeyVersion: String
  ) throws -> [UInt8]? {
    guard case .messageCreate(let create)? = raw.detail,
      let version = create.conversationKeyVersion
    else { return nil }
    if usesMessageKey(raw) {
      return try deriveMessageKey(
        conversationKey: conversationKey,
        senderId: raw.senderId ?? "",
        messageId: raw.messageId ?? "")
    }
    guard version == conversationKeyVersion else {
      throw XChatError.decryption(
        "the reply target is encrypted with conversation key version '\(version)', "
          + "not '\(conversationKeyVersion)'")
    }
    return conversationKey
  }

  /// The version a new key change in `conversationId` signs at: the send
  /// format's action version, raised to the highest key-change signature
  /// version this instance signed or verified there.
  private func keyChangeSignatureVersion(conversationId: String) -> Int32 {
    let base: Int32 = sendVersion == .v1 ? messageSignatureVersion : currentSignatureVersion
    return max(base, keyChangeSignatureFloors[conversationId] ?? 0)
  }

  private func generateMessageId() -> String {
    var bytes = randomBytes(16)
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    return formatUUID(bytes)
  }

  private func requireSequenceId(_ value: String) throws -> String {
    guard !value.isEmpty else {
      throw XChatError.invalidInput("Invalid target message sequence id: must not be empty")
    }
    return value
  }

  private func requireEmoji(_ value: String) throws -> String {
    guard !value.isEmpty else {
      throw XChatError.invalidInput("Invalid reaction emoji: must not be empty")
    }
    return value
  }
}

// MARK: Conversation id canonicalization

/// Rewrites a caller-supplied conversation id into the form events carry and
/// signatures cover: the two participant user ids colon-separated, ordered by
/// (length, then byte order).
private func canonicalConversationId(_ id: String, senderId: String) -> String {
  if let separator = id.firstIndex(where: { $0 == ":" || $0 == "-" }) {
    let first = String(id[..<separator])
    let second = String(id[id.index(after: separator)...])
    guard isDigits(first), isDigits(second) else { return id }
    return joinSortedPair(first, second)
  }
  guard isDigits(id), isDigits(senderId) else { return id }
  return joinSortedPair(id, senderId)
}

/// Orders the pair by (length, then byte order) and joins it with `:`.
private func joinSortedPair(_ a: String, _ b: String) -> String {
  let aFirst = (a.count, a) <= (b.count, b)
  return aFirst ? "\(a):\(b)" : "\(b):\(a)"
}

private func isDigits(_ value: String) -> Bool {
  !value.isEmpty && value.allSatisfy { $0.isASCII && $0.isNumber }
}

/// Checks a user id in canonical decimal form: digits, no leading zero, a
/// positive 64-bit integer.
private func validateUserId(_ field: String, _ value: String) throws {
  let canonical = Int64(value).map(String.init)
  guard canonical == value, let number = Int64(value), number > 0 else {
    throw XChatError.invalidInput(
      "Invalid \(field) '\(value)': pass a numeric user id (digits only)")
  }
}

/// Checks a key version as the X API returns it: a non-negative integer in
/// canonical decimal form.
private func validateKeyVersion(_ field: String, _ value: String) throws {
  let canonical = Int64(value).map(String.init)
  guard canonical == value, let number = Int64(value), number >= 0 else {
    throw XChatError.invalidInput(
      "Invalid \(field) '\(value)': pass the key version as the X API returns it, "
        + "an integer in digits")
  }
}
