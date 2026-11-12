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
    /// conversation key or per-message key. Failures name the media.
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
    /// resolved like `decryptFile`.
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
        try requireFileKey(key)
        return try XChat.encryptFile(key: key, plaintext: file)
    }

    /// Decrypts a file encrypted under a key the caller holds, such as a
    /// group's avatar image under its conversation key.
    public func decryptFileWithKey(_ encrypted: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try requireFileKey(key)
        do {
            return try XChat.decryptFile(key: key, ciphertext: encrypted)
        } catch {
            if let error = error as? XChatError, error.kind == .decryption {
                throw XChatError.decryption(
                    "the bytes are not a complete file encrypted under this key "
                        + "(\(error.message)): pass all the encrypted bytes and the key they "
                        + "were encrypted under")
            }
            throw error
        }
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

    enum KeySource {
        case map
        case single
    }

    /// The key of the media file `mediaHashKey` names in a received message.
    func mediaKey(
        eventB64: String,
        conversationKeys: [String: [UInt8]],
        mediaHashKey: String
    ) throws -> [UInt8] {
        guard !mediaHashKey.isEmpty else {
            throw XChatError.invalidInput(
                "media_hash_key is empty: pass the media hash key of the attachment, from the "
                    + "message decryptEvent returned")
        }
        let event = try parseEvent(eventB64)
        guard case .messageCreate(let create)? = event.detail else {
            throw XChatError.invalidInput(
                "the event is not a message, so it has no media: pass the event of the message "
                    + "that carries the media")
        }
        let message = try openMessage(
            event, create, conversationKeys: conversationKeys, carriedMessageKey: nil,
            which: "the message", keySource: .map)
        if let key = try attachmentKey(message, mediaHashKey: mediaHashKey) {
            return key
        }

        var known = mediaHashKeys(message.contents.attachments)
        if let preview = message.contents.replyingToPreview {
            let shown = mediaHashKeys(preview.attachments)
            do {
                let quoted = try openQuoted(
                    event, preview: preview, conversationKeys: conversationKeys)
                if let key = try attachmentKey(quoted, mediaHashKey: mediaHashKey) {
                    return key
                }
                known += mediaHashKeys(quoted.contents.attachments)
            } catch {
                // When the preview shows this media, why its message cannot
                // be opened is the answer; otherwise it is not quoted here.
                if shown.contains(mediaHashKey) { throw error }
                known += shown
            }
        }

        if known.isEmpty {
            throw XChatError.invalidInput(
                "the message has no media: pass the event of the message that carries the media")
        }
        throw XChatError.invalidInput(
            "media_hash_key '\(mediaHashKey)' is not in the message, whose media hash keys are "
                + "\(known.joined(separator: ", ")): pass one of those, or the event of the "
                + "message that carries this media")
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
        guard !mediaHashKey.isEmpty else {
            throw XChatError.invalidInput(
                "media_hash_key is empty: pass the media hash key the file's upload started "
                    + "with, as listed in the message's attachments")
        }
        let event = try parseEvent(eventB64)
        guard case .messageCreate(let create)? = event.detail else {
            throw XChatError.invalidInput(
                "the event is not a message: pass the eventB64 of the payload that encryptMessage "
                    + "or encryptReply returned")
        }
        let message = try openMessage(
            event, create,
            conversationKeys: [conversationKeyVersion: conversationKey],
            carriedMessageKey: nil, which: "the message", keySource: .single)
        if let key = try attachmentKey(message, mediaHashKey: mediaHashKey) {
            return key
        }

        let quoted = mediaHashKeys(message.contents.replyingToPreview?.attachments)
        if quoted.contains(mediaHashKey) {
            throw XChatError.invalidInput(
                "media_hash_key '\(mediaHashKey)' is media the reply quotes: its file belongs "
                    + "to the quoted message and was uploaded with it, so there is nothing to "
                    + "encrypt")
        }
        let own = mediaHashKeys(message.contents.attachments)
        if own.isEmpty {
            throw XChatError.invalidInput(
                "the message has no files: list each file's media hash key in the message's "
                    + "attachments, then encrypt the file with the payload that returns")
        }
        throw XChatError.invalidInput(
            "media_hash_key '\(mediaHashKey)' is not one of the message's files, whose media "
                + "hash keys are \(own.joined(separator: ", ")): pass one of those, or list this "
                + "file in the message's attachments")
    }

    /// Decrypts a message event's contents and reports what its attachments'
    /// keys come from.
    func openMessage(
        _ event: MessageEvent,
        _ create: MessageCreateEvent,
        conversationKeys: [String: [UInt8]],
        carriedMessageKey: [UInt8]?,
        which: String,
        keySource: KeySource
    ) throws -> OpenedMessage {
        guard let version = create.conversationKeyVersion else {
            throw XChatError.invalidInput(
                "\(which) is not encrypted, so neither is its media: use the downloaded bytes "
                    + "as they are")
        }
        let carried =
            usesMessageKey(create.contentsEncryptionVersion.map { Int($0) })
            ? carriedMessageKey : nil

        let keys: AttachmentKeys
        let source: String
        if let conversationKey = conversationKeys[version] {
            if let messageKey = try messageKeyFor(
                event, create: create, conversationKey: conversationKey)
            {
                keys = .message(
                    key: messageKey, messageId: try requireMessageId(event, which))
                source =
                    keySource == .map
                    ? "the key for version '\(version)' in conversationKeys"
                    : "conversationKey (version '\(version)')"
            } else {
                keys = .conversation(conversationKey)
                source =
                    keySource == .map
                    ? "the key for version '\(version)' in conversationKeys"
                    : "conversationKey (version '\(version)')"
            }
        } else if let carried {
            guard carried.count == 32 else {
                throw XChatError.invalidInput(
                    "the key the reply carries for \(which) is not 32 bytes: pass \(which)'s "
                        + "own event")
            }
            keys = .message(key: carried, messageId: try requireMessageId(event, which))
            source = "the key the reply carries for \(which)"
        } else {
            let versions = conversationKeys.keys.sorted().joined(separator: ", ")
            throw XChatError.decryption(
                "conversationKeys has no key for version '\(version)', which \(which) is "
                    + "encrypted under (it has versions [\(versions)]): pass the conversation's "
                    + "key map from decryptEvents or extractConversationKeys, including version "
                    + "'\(version)'")
        }

        guard let contents = create.contents else {
            throw XChatError.invalidInput("\(which) has no contents")
        }
        let contentsKey: [UInt8]
        switch keys {
        case .conversation(let key): contentsKey = key
        case .message(let key, _): contentsKey = key
        }
        let plaintext: [UInt8]
        do {
            plaintext = try decryptMessage(key: contentsKey, ciphertext: contents)
        } catch {
            throw XChatError.decryption(
                "\(source) does not decrypt \(which): pass the conversation key for version "
                    + "'\(version)'")
        }

        var reader = ThriftReader(plaintext)
        let holder: MessageEntryHolder
        do {
            holder = try MessageEntryHolder.read(&reader)
        } catch {
            throw XChatError.parse(
                "Content parse error: \((error as? XChatError)?.message ?? String(describing: error))")
        }
        switch holder.contents {
        case .message(let message):
            return OpenedMessage(contents: message, keys: keys)
        case .messageEdit:
            throw XChatError.invalidInput(
                "\(which) is an edit, and edits carry no media: pass the event of the message "
                    + "that was edited")
        default:
            throw XChatError.invalidInput(
                "\(which) is a reaction, read marker, or other entry without media: pass the "
                    + "event of the message that carries the media")
        }
    }

    /// Decrypts the message a reply quotes, embedded in its preview.
    private func openQuoted(
        _ reply: MessageEvent,
        preview: ReplyingToPreview,
        conversationKeys: [String: [UInt8]]
    ) throws -> OpenedMessage {
        guard let quoted = preview.rawEventMessageCreate else {
            throw XChatError.invalidInput(
                "the reply does not embed the message it quotes, so that message's media can't "
                    + "be opened through the reply: pass the quoted message's own event")
        }
        guard let conversationId = quoted.conversationId,
            conversationId == reply.conversationId
        else {
            throw XChatError.invalidInput(
                "the reply quotes a message from another conversation: pass the quoted "
                    + "message's own event")
        }
        guard case .messageCreate(let create)? = quoted.detail else {
            throw XChatError.invalidInput(
                "the reply's quoted event is not a message: pass the event of the message that "
                    + "carries the media")
        }
        return try openMessage(
            quoted, create, conversationKeys: conversationKeys,
            carriedMessageKey: preview.rawEventMessageKey,
            which: "the quoted message", keySource: .map)
    }

    /// The key of the attachment carrying `mediaHashKey`, when the message
    /// has one.
    private func attachmentKey(
        _ message: OpenedMessage, mediaHashKey: String
    ) throws -> [UInt8]? {
        guard
            let found = findAttachment(
                message.contents.attachments, mediaHashKey: mediaHashKey)
        else { return nil }
        switch message.keys {
        case .conversation(let key):
            return key
        case .message(let messageKey, let messageId):
            return try deriveAttachmentKey(
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

    private func requireMessageId(_ event: MessageEvent, _ which: String) throws -> String {
        guard let messageId = event.messageId else {
            throw XChatError.invalidInput("\(which) has no message id")
        }
        return messageId
    }

    private func requireFileKey(_ key: [UInt8]) throws {
        guard key.count == 32 else {
            throw XChatError.invalidInput(
                "Invalid key (expected 32 bytes, got \(key.count))")
        }
    }
}
