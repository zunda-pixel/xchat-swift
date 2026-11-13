/// The SDK core: key state, event decryption, and reply-preview validation.
///
/// It performs no networking and stores nothing on disk; conversation keys
/// given to it, and those it adopts from verified key changes, live in
/// memory for this instance's lifetime.
public final class XChatCore {
  /// Whether an event whose signature cannot be verified is rejected.
  ///
  /// On by default: a message or key change that cannot be verified never
  /// yields plaintext. Turn it off only to inspect unverified traffic.
  public let rejectUnverified: Bool

  /// The identity private key, used by key handling and file decryption.
  var identityPrivateKey: [UInt8]?
  /// The signing key, used by the send path.
  var signingPrivateKey: [UInt8]?
  /// The public-key version the loaded keys were registered under.
  var keyVersion: String?

  /// The wire format messages are sent in: v0 unless the app opts into v1
  /// (per-message keys), which v1 media sends require.
  public var sendVersion: SendVersion = .v0

  /// The feature switches the last accepted answer turned on. Every switch
  /// is off until an answer turns one on, so sends stay v0 (fail-closed).
  public internal(set) var features: FeatureSwitches = .off

  /// Highest key-change signature version signed or verified per
  /// conversation; new key changes sign at no lower a version.
  var keyChangeSignatureFloors: [String: Int32] = [:]

  /// Highest verified conversation-key version per conversation, held for
  /// this instance's lifetime so a replayed older key change cannot lower
  /// it.
  private var keyHighWater: [String: UInt64] = [:]

  public init(rejectUnverified: Bool = true) {
    self.rejectUnverified = rejectUnverified
  }

  /// Whether an identity private key is loaded.
  public var isUnlocked: Bool { identityPrivateKey != nil }

  /// The public-key version the loaded keys were registered under.
  public var publicKeyVersion: String? { keyVersion }

  /// Loads this device's private keys. `signingPrivateKey` may be omitted
  /// for identity-only use, and `publicKeyVersion` is the version the keys
  /// were registered under, which selects the participant key a key change
  /// carries for this device.
  public func importKeys(
    identityPrivateKey: [UInt8],
    signingPrivateKey: [UInt8]? = nil,
    publicKeyVersion: String? = nil
  ) throws {
    _ = try parsePrivateKey(identityPrivateKey)
    if let signingPrivateKey {
      _ = try parsePrivateKey(signingPrivateKey)
    }
    if let publicKeyVersion {
      try validatePublicKeyVersion(publicKeyVersion)
    }
    self.identityPrivateKey = identityPrivateKey
    self.signingPrivateKey = signingPrivateKey
    self.keyVersion = publicKeyVersion
  }

  /// The loaded private keys, for the caller's own storage. The caller owns
  /// wiping the returned bytes.
  public func exportKeys() throws -> (identity: [UInt8], signing: [UInt8]?) {
    guard let identityPrivateKey else {
      throw XChatError.invalidState("keys are not loaded: import keys first")
    }
    return (identityPrivateKey, signingPrivateKey)
  }

  /// The loaded identity key's SEC1 public key (65 bytes).
  public func identityPublicKey() throws -> [UInt8] {
    guard let identityPrivateKey else {
      throw XChatError.invalidState("keys are not loaded: import keys first")
    }
    return try derivePublicKey(privateKey: identityPrivateKey)
  }

  /// The loaded signing key's SEC1 public key (65 bytes), when present.
  public func signingPublicKey() throws -> [UInt8]? {
    guard let signingPrivateKey else { return nil }
    return try derivePublicKey(privateKey: signingPrivateKey)
  }

  // MARK: Decryption

  /// Decrypts one event. Throws when the event is malformed, when its
  /// signature is missing or invalid under the reject-unverified policy,
  /// when its conversation key was not supplied, or when its contents do
  /// not decrypt. For key-change verification, a caller-supplied key can
  /// be used when this device cannot decrypt a key from the event.
  public func decryptEvent(
    _ eventB64: String,
    conversationKeys: [String: [UInt8]] = [:],
    signingKeys: [SigningKeyEntry] = []
  ) throws -> XChatEvent {
    let parsed = try parseEvent(eventB64)
    let verifiedKeys = verifiedSigningKeys(signingKeys)
    return try decryptParsed(
      parsed,
      keys: conversationKeys,
      signingKeys: verifiedKeys.filter { $0.userId == parsed.senderId },
      allSigningKeys: verifiedKeys)
  }

  /// Decrypts a batch of events in one pass.
  ///
  /// Conversation keys carried by `ConversationKeyChange` events are
  /// returned for caching only after verifying each event against its
  /// own decrypted key. This applies even when inspecting unverified events.
  /// Per-event failures — malformed events, failed verification, missing
  /// keys — are collected in `errors` by index instead of throwing, so one
  /// bad event never hides the rest. Caller-supplied `conversationKeys`
  /// take precedence over adopted ones.
  public func decryptEvents(
    _ events: [String],
    conversationKeys: [String: [UInt8]] = [:],
    signingKeys: [SigningKeyEntry] = []
  ) -> DecryptEventsResult {
    let verifiedKeys = verifiedSigningKeys(signingKeys)
    let parsed: [Result<MessageEvent, XChatError>] = events.map { eventB64 in
      do {
        return .success(try parseEvent(eventB64))
      } catch let error as XChatError {
        return .failure(error)
      } catch {
        return .failure(.internalError(String(describing: error)))
      }
    }

    var keys: [String: [UInt8]] = [:]
    var conflictingVersions: Set<String> = []
    var keyChanges: [Int: KeyChange] = [:]
    var verifiedKeyIndices: [Int] = []
    var errors: [Int: String] = [:]
    var batchConversations: Set<String> = []
    for (index, result) in parsed.enumerated() {
      guard let event = try? result.get() else { continue }
      if let conversationId = event.conversationId {
        batchConversations.insert(conversationId)
      }
      guard case .conversationKeyChange(let change)? = event.detail else { continue }
      let key = decryptKeyChangeCkey(change)
      let verificationKey = key ?? change.conversationKeyVersion.flatMap { conversationKeys[$0] }
      do {
        let keyChange = try decryptKeyChangeEvent(
          event, change, plaintextKey: verificationKey,
          signingKeys: verifiedKeys.filter { $0.userId == event.senderId })
        keyChanges[index] = keyChange
        guard keyChange.verified, let key, let version = change.conversationKeyVersion,
          !conflictingVersions.contains(version)
        else { continue }

        verifiedKeyIndices.append(index)

        // The cache is keyed by version alone, so conflicting signed keys
        // cannot be selected without a caller-supplied key.
        if let previous = keys[version], previous != key {
          keys.removeValue(forKey: version)
          conflictingVersions.insert(version)
        } else {
          keys[version] = key
        }
      } catch {
        errors[index] = reason(of: error)
      }
    }

    // Only an adopted key covered by a plaintext signature raises the
    // reported latest version. Replaying an older one cannot lower it.
    for index in verifiedKeyIndices {
      guard let change = keyChanges[index], let event = try? parsed[index].get(),
        let conversationId = event.conversationId,
        let version = UInt64(change.conversationKeyVersion),
        keys[change.conversationKeyVersion] != nil,
        signatureVersion(of: event).map({ $0 >= conversationKeyPlaintextSignatureVersion }) == true
      else { continue }
      keyHighWater[conversationId] = max(keyHighWater[conversationId] ?? 0, version)
    }

    // The caller's map wins over adopted keys.
    for (version, key) in conversationKeys {
      keys[version] = key
    }

    var decrypted: [DecryptedEvent] = []
    for (index, eventB64) in events.enumerated() {
      if let change = keyChanges[index] {
        decrypted.append(DecryptedEvent(event: .keyChange(change), originalB64: eventB64))
        continue
      }
      guard errors[index] == nil else { continue }
      do {
        let event = try parsed[index].get()
        let senderKeys = verifiedKeys.filter { $0.userId == event.senderId }
        let decryptedEvent = try decryptParsed(
          event, keys: keys, signingKeys: senderKeys, allSigningKeys: verifiedKeys)
        decrypted.append(
          DecryptedEvent(event: decryptedEvent, originalB64: eventB64))
      } catch {
        errors[index] = (error as? XChatError)?.message ?? String(describing: error)
      }
    }

    let latestVersion =
      batchConversations
      .compactMap { keyHighWater[$0] }
      .max()
      .map(String.init)
    return DecryptEventsResult(
      events: decrypted,
      conversationKeys: ConversationKeySet(keys: keys, latestVersion: latestVersion),
      errors: errors)
  }

  // MARK: Event dispatch

  private func decryptParsed(
    _ parsed: MessageEvent,
    keys: [String: [UInt8]],
    signingKeys: [SigningKeyEntry],
    allSigningKeys: [SigningKeyEntry]
  ) throws -> XChatEvent {
    let meta = eventMeta(parsed)

    guard let detail = parsed.detail else {
      return .unsupported(UnsupportedEvent(meta: meta, verified: false))
    }
    switch detail {
    case .messageCreate(let create):
      return try decryptMessageEvent(
        parsed, create, meta: meta, keys: keys, signingKeys: signingKeys,
        allSigningKeys: allSigningKeys)
    case .conversationKeyChange(let change):
      let key = decryptKeyChangeCkey(change) ?? change.conversationKeyVersion.flatMap { keys[$0] }
      return .keyChange(
        try decryptKeyChangeEvent(
          parsed, change, plaintextKey: key, signingKeys: signingKeys))
    case .messageTyping(let typing):
      return .typing(
        Typing(
          meta: meta,
          activityType: typing.activityType,
          createdAtMilliseconds: typing.createdAtMilliseconds))
    case .messageFailure(let failure):
      return .failure(
        Failure(
          meta: meta, failureType: failure.failureType,
          rateLimitTier: failure.rateLimitTier))
    case .messageDelete, .conversationDelete:
      // Deletes are outside this SDK's actions; report whether the
      // event verified without enforcing the policy on them.
      let check = checkEventSignature(
        event: parsed, detail: detail, signingKeys: signatureKeys(signingKeys))
      return .unsupported(UnsupportedEvent(meta: meta, verified: check == .verified))
    case .unsupported:
      return .unsupported(UnsupportedEvent(meta: meta, verified: false))
    }
  }

  private func decryptMessageEvent(
    _ parsed: MessageEvent,
    _ create: MessageCreateEvent,
    meta: EventMeta,
    keys: [String: [UInt8]],
    signingKeys: [SigningKeyEntry],
    allSigningKeys: [SigningKeyEntry]
  ) throws -> XChatEvent {
    guard let contents = create.contents else {
      return .unsupported(UnsupportedEvent(meta: meta, verified: false))
    }

    // An unencrypted message has no conversation-key version; its
    // contents are already plaintext Thrift bytes and it carries no
    // signature, so it is unverifiable either way.
    let unencrypted = create.conversationKeyVersion == nil
    let check: EventSignatureCheck =
      unencrypted
      ? .unverifiable
      : checkEventSignature(
        event: parsed, detail: .messageCreate(create),
        signingKeys: signatureKeys(signingKeys))
    try enforceVerification(check, label: "Message")

    let plaintext: [UInt8]
    if unencrypted {
      plaintext = contents
    } else {
      let version = create.conversationKeyVersion ?? ""
      guard let conversationKey = keys[version] else {
        let available = keys.keys.sorted().joined(separator: ", ")
        throw XChatError.decryption(
          "Message encrypted with key version '\(version)' but no matching key found. "
            + "Available versions: [\(available)]. Include the conversation's "
            + "KeyChange events in the batch passed to decryptEvents(), or pass the "
            + "matching key map to decryptEvent().")
      }
      let messageKey = try messageKeyFor(parsed, create: create, conversationKey: conversationKey)
      plaintext = try decryptMessage(
        key: messageKey ?? conversationKey, ciphertext: contents)
    }

    let content = try parseMessageContent(plaintext)
    var replyPreviewValidation: ReplyPreviewValidation?
    if let preview = content.rawPreview, preview.rawEventMessageCreate != nil {
      replyPreviewValidation = validateReplyPreview(
        outer: parsed, preview: preview, keys: keys, allSigningKeys: allSigningKeys)
    }

    return .message(
      Message(
        meta: meta,
        content: content.content,
        conversationKeyVersion: create.conversationKeyVersion,
        verified: check == .verified,
        shouldNotify: create.shouldNotify,
        ttlMilliseconds: create.ttlMilliseconds,
        attachments: content.attachments,
        mediaHashes: content.mediaHashes,
        replyPreviewValidation: replyPreviewValidation))
  }

  private func decryptKeyChangeEvent(
    _ parsed: MessageEvent,
    _ change: ConversationKeyChangeEvent,
    plaintextKey: [UInt8]?,
    signingKeys: [SigningKeyEntry]
  ) throws -> KeyChange {
    let version = change.conversationKeyVersion ?? ""
    let check = checkEventSignature(
      event: parsed, detail: .conversationKeyChange(change),
      signingKeys: signatureKeys(signingKeys),
      plaintextConversationKeyB64: plaintextKey.map(Base64.encodeStandard))
    try enforceVerification(check, label: "KeyChange")
    if check == .verified, let conversationId = parsed.conversationId,
      let version = signatureVersion(of: parsed)
    {
      keyChangeSignatureFloors[conversationId] = max(
        keyChangeSignatureFloors[conversationId] ?? 0, version)
    }

    let participants = (change.conversationParticipantKeys ?? []).compactMap {
      key -> ParticipantKey? in
      guard let userId = key.userId, let encrypted = key.encryptedConversationKey else {
        return nil
      }
      return ParticipantKey(
        userId: userId, encryptedConversationKey: encrypted,
        publicKeyVersion: key.publicKeyVersion ?? "")
    }
    return KeyChange(
      meta: eventMeta(parsed), conversationKeyVersion: version,
      verified: check == .verified, participantKeys: participants)
  }

  // MARK: Key handling

  /// Throws under the reject-unverified policy unless `check` verified.
  private func enforceVerification(_ check: EventSignatureCheck, label: String) throws {
    guard rejectUnverified else { return }
    switch check {
    case .verified:
      return
    case .unverifiable:
      throw XChatError.verification(
        "\(label) signature could not be verified: "
          + "signature missing or no matching signing key")
    case .failed(let reason):
      throw XChatError.verification(
        "\(label) signature verification failed: \(reason)")
    }
  }

  /// Drops signing keys whose identity-key binding does not verify, so a
  /// key that claims a binding it does not have cannot verify events.
  private func verifiedSigningKeys(_ entries: [SigningKeyEntry]) -> [SigningKeyEntry] {
    entries.filter { entry in
      if entry.identityPublicKey == nil, entry.identityPublicKeySignature == nil,
        entry.signingPublicKeySignature == nil
      {
        return true
      }
      guard let identityB64 = entry.identityPublicKey,
        let signatureB64 = entry.signingPublicKeySignature,
        let identity = try? Base64.decodeStandard(identityB64),
        let signature = try? Base64.decodeStandard(signatureB64),
        let signingKey = try? Base64.decodeStandard(entry.publicKey),
        let signingSPKI = try? spkiDER(publicKey: signingKey)
      else { return false }
      return
        (try? verify(
          publicKey: identity, signature: signature, payload: signingSPKI)) ?? false
    }
  }

  /// The per-message key a v1 message uses, derived from its conversation
  /// key and the event's own sender and message id; nil for v0 messages.
  func messageKeyFor(
    _ parsed: MessageEvent,
    create: MessageCreateEvent,
    conversationKey: [UInt8]
  ) throws -> [UInt8]? {
    guard usesMessageKey(create.contentsEncryptionVersion.map { Int($0) }) else {
      return nil
    }
    guard let senderId = parsed.senderId, let messageId = parsed.messageId else {
      throw XChatError.decryption(
        "message key needs the event's sender id and message id")
    }
    return try deriveMessageKey(
      conversationKey: conversationKey, senderId: senderId, messageId: messageId)
  }

  /// Decrypts the conversation key a key change carries for this device,
  /// preferring the entry matching the loaded key version and trying each
  /// decryptable entry. Nil when locked or none decrypts.
  private func decryptKeyChangeCkey(_ change: ConversationKeyChangeEvent) -> [UInt8]? {
    guard let identity = identityPrivateKey,
      let participants = change.conversationParticipantKeys
    else { return nil }
    for participant in participants {
      if let mine = keyVersion, let theirs = participant.publicKeyVersion,
        theirs != mine
      {
        continue
      }
      guard let encryptedB64 = participant.encryptedConversationKey,
        let encrypted = try? Base64.decodeStandard(encryptedB64)
      else { continue }
      if let key = try? decryptWithPrivateKey(privateKey: identity, data: encrypted),
        key.count == 32
      {
        return key
      }
    }
    return nil
  }

  // MARK: Parsing

  func parseEvent(_ eventB64: String) throws -> MessageEvent {
    let bytes: [UInt8]
    do {
      bytes = try Base64.decodeStandard(eventB64)
    } catch {
      throw XChatError.parse("Invalid base64 event: \(reason(of: error))")
    }
    var reader = ThriftReader(bytes)
    do {
      return try MessageEvent.read(&reader)
    } catch {
      throw XChatError.parse("Thrift parse error: \(reason(of: error))")
    }
  }
}

/// Converts verified signing-key entries into the form the signature layer
/// checks, which selects keys by version alone.
private func signatureKeys(_ entries: [SigningKeyEntry]) -> [SigningKey] {
  entries.map { SigningKey(publicKeyVersion: $0.publicKeyVersion, publicKey: $0.publicKey) }
}

private func eventMeta(_ event: MessageEvent) -> EventMeta {
  EventMeta(
    sequenceId: event.sequenceId, messageId: event.messageId, senderId: event.senderId,
    conversationId: event.conversationId,
    createdAtMilliseconds: event.createdAtMilliseconds.flatMap(Int64.init))
}

private func reason(of error: some Error) -> String {
  (error as? XChatError)?.message ?? String(describing: error)
}

/// A decrypted payload, with the wire preview kept for validation.
private struct ParsedMessageContent {
  var content: MessageContent
  var attachments: [AttachmentInfo]
  var mediaHashes: [MediaHashReference]
  var rawPreview: ReplyingToPreview?
}

private func parseMessageContent(_ bytes: [UInt8]) throws -> ParsedMessageContent {
  var reader = ThriftReader(bytes)
  let holder: MessageEntryHolder
  do {
    holder = try MessageEntryHolder.read(&reader)
  } catch {
    throw XChatError.parse("Content parse error: \(reason(of: error))")
  }

  var attachments: [AttachmentInfo] = []
  var mediaHashes: [MediaHashReference] = []
  var rawPreview: ReplyingToPreview?
  let content: MessageContent

  switch holder.contents {
  case .message(let message):
    (attachments, mediaHashes) = collectAttachments(message.attachments)
    rawPreview = message.replyingToPreview
    content = .text(
      TextContent(
        text: message.messageText ?? "",
        entities: message.entities.map { $0.map(mapEntity) },
        attachments: attachments,
        replyingToPreview: message.replyingToPreview.map(mapPreview),
        forwardedMessage: message.forwardedMessage.map {
          ForwardedContent(
            text: $0.messageText,
            entities: $0.entities.map { $0.map(mapEntity) })
        },
        sentFrom: message.sentFrom,
        quickReply: message.quickReply.flatMap(mapQuickReply),
        callToActions: message.callToActions.map {
          $0.map { CallToActionInfo(label: $0.label, url: $0.url) }
        }))
  case .reactionAdd(let reaction):
    content = .reaction(
      emoji: reaction.emoji ?? "",
      targetMessageSequenceId: reaction.messageSequenceId ?? "")
  case .reactionRemove(let reaction):
    content = .reactionRemoved(
      emoji: reaction.emoji ?? "",
      targetMessageSequenceId: reaction.messageSequenceId ?? "")
  case .messageEdit(let edit):
    content = .edit(
      targetMessageSequenceId: edit.messageSequenceId ?? "",
      targetMessageId: edit.messageId,
      updatedText: edit.updatedText ?? "",
      entities: edit.entities.map { $0.map(mapEntity) })
  case .markConversationRead:
    content = .markRead
  case .markConversationUnread:
    content = .markUnread
  case .unsupported, nil:
    content = .unknown
  }

  return ParsedMessageContent(
    content: content, attachments: attachments, mediaHashes: mediaHashes,
    rawPreview: rawPreview)
}

private func mapEntity(_ entity: RichTextEntity) -> RichTextEntityInfo {
  RichTextEntityInfo(
    startIndex: entity.startIndex, endIndex: entity.endIndex,
    kind: entity.content.flatMap(mapEntityKind))
}

private func mapEntityKind(_ content: RichTextContent) -> EntityKind? {
  switch content {
  case .hashtag: .hashtag
  case .cashtag: .cashtag
  case .mention: .mention
  case .url: .url
  case .email: .email
  case .address: .address
  case .phoneNumber: .phoneNumber
  case .unsupported: nil
  }
}

private func mapPreview(_ preview: ReplyingToPreview) -> ReplyPreview {
  ReplyPreview(
    senderId: preview.senderId.map(String.init),
    messageText: preview.messageText,
    entities: preview.entities.map { $0.map(mapEntity) },
    attachments: preview.attachments?.compactMap(mapAttachment),
    senderDisplayName: nil,
    messageSequenceId: nil,
    messageId: preview.messageId,
    attachmentId: nil,
    embedsSourceEvent: preview.rawEventMessageCreate != nil)
}

private func mapQuickReply(_ quickReply: QuickReply) -> QuickReplyInfo? {
  switch quickReply {
  case .request(let request):
    guard let options = request.options else { return nil }
    return QuickReplyInfo(
      content: .request(
        id: options.id,
        options: (options.options ?? []).map {
          QuickReplyOptionInfo(
            id: $0.id, label: $0.label, metadata: $0.metadata,
            optionDescription: $0.optionDescription)
        }))
  case .response(let response):
    guard let options = response.options else { return nil }
    return QuickReplyInfo(
      content: .response(
        requestId: options.requestId, metadata: options.metadata,
        selectedOptionId: options.selectedOptionId))
  case .unsupported:
    return nil
  }
}

private func mapMediaType(_ type: MediaType?) -> String? {
  switch type {
  case .image: "image"
  case .gif: "gif"
  case .video: "video"
  case .audio: "audio"
  case .file: "file"
  case .svg: "svg"
  case nil: nil
  }
}

private func mapDimensions(_ dimensions: MediaDimensions?) -> MediaDimensionsInfo? {
  guard let dimensions else { return nil }
  return MediaDimensionsInfo(width: dimensions.width, height: dimensions.height)
}

private func mapAttachment(_ attachment: MessageAttachment) -> AttachmentInfo? {
  switch attachment {
  case .media(let media):
    return .media(
      MediaAttachmentInfo(
        mediaHashKey: media.mediaHashKey,
        dimensions: mapDimensions(media.dimensions),
        mediaType: mapMediaType(media.type),
        durationMilliseconds: media.durationMilliseconds,
        filesizeBytes: media.filesizeBytes,
        filename: media.filename,
        attachmentId: media.attachmentId,
        legacyMediaURLHTTPS: media.legacyMediaURLHTTPS,
        legacyMediaPreviewURL: media.legacyMediaPreviewURL,
        plaintextSHA256: media.plaintextSHA256))
  case .url(let url):
    return .url(
      UrlAttachmentInfo(
        url: url.url,
        bannerImageMediaHashKey: url.bannerImage?.mediaHashKey,
        faviconImageMediaHashKey: url.faviconImage?.mediaHashKey,
        displayTitle: url.displayTitle,
        attachmentId: url.attachmentId))
  case .post(let post):
    return .post(
      PostAttachmentInfo(
        restId: post.restId, postURL: post.postURL,
        attachmentId: post.attachmentId))
  case .unifiedCard(let card):
    return .unifiedCard(
      UnifiedCardAttachmentInfo(url: card.url, attachmentId: card.attachmentId))
  case .money(let money):
    return .money(MoneyAttachmentInfo(fallbackText: money.fallbackText))
  case .unsupported:
    return nil
  }
}

private func collectAttachments(
  _ attachments: [MessageAttachment]?
) -> ([AttachmentInfo], [MediaHashReference]) {
  var parsed: [AttachmentInfo] = []
  var mediaHashes: [MediaHashReference] = []
  for attachment in attachments ?? [] {
    switch attachment {
    case .media(let media):
      if let hash = media.mediaHashKey {
        mediaHashes.append(MediaHashReference(source: "media", mediaHashKey: hash))
      }
    case .url(let url):
      if let hash = url.bannerImage?.mediaHashKey {
        mediaHashes.append(MediaHashReference(source: "url_banner", mediaHashKey: hash))
      }
      if let hash = url.faviconImage?.mediaHashKey {
        mediaHashes.append(MediaHashReference(source: "url_favicon", mediaHashKey: hash))
      }
    case .post, .unifiedCard, .money, .unsupported:
      break
    }
    if let mapped = mapAttachment(attachment) {
      parsed.append(mapped)
    }
  }
  return (parsed, mediaHashes)
}

// MARK: Reply-preview validation

/// Validates a received reply preview against the signed original it embeds:
/// verifies the original's signature, decrypts its contents, and checks
/// every claim the preview makes. Anything that cannot be checked is
/// invalid.
private func validateReplyPreview(
  outer: MessageEvent,
  preview: ReplyingToPreview,
  keys: [String: [UInt8]],
  allSigningKeys: [SigningKeyEntry]
) -> ReplyPreviewValidation {
  guard let raw = preview.rawEventMessageCreate else { return .invalid }
  // The original must belong to the same conversation as the reply;
  // otherwise a participant could attribute words from elsewhere.
  guard let conversationId = raw.conversationId,
    conversationId == outer.conversationId
  else { return .invalid }
  guard case .messageCreate(let rawCreate)? = raw.detail else { return .invalid }

  // Same key selection as top-level events: the raw event's sender's keys.
  guard let rawSender = raw.senderId else { return .invalid }
  let senderKeys = allSigningKeys.filter { $0.userId == rawSender }
  guard
    checkEventSignature(
      event: raw, detail: .messageCreate(rawCreate),
      signingKeys: signatureKeys(senderKeys))
      == .verified
  else { return .invalid }

  guard
    let originalPlaintext = openQuotedEvent(
      raw, carriedKey: preview.rawEventMessageKey, keys: keys),
    let original = parseMessageContents(originalPlaintext)
  else { return .invalid }

  if let claimedSender = preview.senderId {
    guard raw.senderId == String(claimedSender) else { return .invalid }
  }
  if let claimedId = preview.messageId {
    guard raw.messageId == claimedId else { return .invalid }
  }

  // An embedded edit quotes the edited contents; it must verify like the
  // original and come from the original's author.
  var edited: MessageEdit?
  if let edit = preview.rawEventEditMessage {
    guard let editConversation = edit.conversationId,
      editConversation == outer.conversationId,
      let editSender = edit.senderId, editSender == raw.senderId,
      case .messageCreate(let editCreate)? = edit.detail,
      checkEventSignature(
        event: edit, detail: .messageCreate(editCreate),
        signingKeys: signatureKeys(senderKeys))
        == .verified,
      let editPlaintext = openQuotedEvent(
        edit, carriedKey: preview.rawEventEditMessageKey, keys: keys),
      let editContents = parseMessageEdit(editPlaintext)
    else { return .invalid }
    // A v0 original's sequence ID is unsigned. Require the signed message ID
    // of a message-key original to bind the edit to its target.
    guard usesMessageKey(raw), let editMessageId = editContents.messageId,
      editMessageId == raw.messageId
    else { return .invalid }
    edited = editContents
  }

  let quotedText = (edited?.updatedText ?? original.messageText ?? "").utf16
  let claimedText = (preview.messageText ?? "").utf16
  let entitiesMatch = edited.map { $0.entities } ?? original.entities
  // Require the protocol's preview prefix and authenticate every extra code
  // unit a sender includes, since the API exposes the full claimed text.
  guard claimedText.count >= quotedText.prefix(140).count,
    quotedText.starts(with: claimedText),
    preview.entities == entitiesMatch
  else { return .invalid }

  if let claimedAttachments = preview.attachments {
    let originalAttachments = original.attachments ?? []
    for attachment in claimedAttachments where mapAttachment(attachment) != nil {
      guard originalAttachments.contains(where: { matchesAttachmentClaim(attachment, $0) })
      else { return .invalid }
    }
  }
  return .valid
}

/// Decrypts a quoted message event's contents into the holder's plaintext
/// bytes, or returns nil when its key is unknown.
private func openQuotedEvent(
  _ raw: MessageEvent,
  carriedKey: [UInt8]?,
  keys: [String: [UInt8]]
) -> [UInt8]? {
  guard case .messageCreate(let create)? = raw.detail, let contents = create.contents else {
    return nil
  }
  let usesMessageKey = usesMessageKey(raw)
  let key: [UInt8]?
  if usesMessageKey, let carriedKey, carriedKey.count == 32 {
    key = carriedKey
  } else if let version = create.conversationKeyVersion, let conversationKey = keys[version] {
    key =
      usesMessageKey
      ? (try? deriveMessageKey(
        conversationKey: conversationKey,
        senderId: raw.senderId ?? "",
        messageId: raw.messageId ?? ""))
      : conversationKey
  } else {
    key = nil
  }
  guard let key else { return nil }
  return try? decryptMessage(key: key, ciphertext: contents)
}

/// Parses a quoted message's decrypted bytes into its text contents.
private func parseMessageContents(_ bytes: [UInt8]) -> MessageContents? {
  var reader = ThriftReader(bytes)
  guard let holder = try? MessageEntryHolder.read(&reader) else { return nil }
  guard case .message(let message)? = holder.contents else { return nil }
  return message
}

/// Whether a raw event's contents use a per-message key.
func usesMessageKey(_ raw: MessageEvent) -> Bool {
  guard case .messageCreate(let create)? = raw.detail else { return false }
  return usesMessageKey(create.contentsEncryptionVersion.map { Int($0) })
}

private func parseMessageEdit(_ bytes: [UInt8]) -> MessageEdit? {
  var reader = ThriftReader(bytes)
  guard let holder = try? MessageEntryHolder.read(&reader) else { return nil }
  guard case .messageEdit(let edit)? = holder.contents else { return nil }
  return edit
}

/// A preview may omit the digest, but any digest it supplies must match.
private func matchesAttachmentClaim(
  _ claim: MessageAttachment, _ original: MessageAttachment
) -> Bool {
  if case .media(let media) = claim, media.plaintextSHA256 == nil,
    case .media(var sourceMedia) = original
  {
    sourceMedia.plaintextSHA256 = nil
    return claim == .media(sourceMedia)
  }
  return claim == original
}
