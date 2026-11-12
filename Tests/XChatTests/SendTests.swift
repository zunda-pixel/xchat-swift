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
            throw XChatError.parse("expected a message event")
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
        XCTAssertEqual(message.content, .text(
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

    // MARK: Validation

    func testSendValidation() throws {
        let (core, _) = try makeCore()
        func send(
            key: [UInt8] = Self.conversationKey,
            version: String = Self.conversationKeyVersion,
            entities: [EntityDescriptor]? = nil,
            attachments: [AttachmentDescriptor]? = nil
        ) throws {
            _ = try core.encryptMessage(
                text: "x", conversationId: Self.conversationId, conversationKey: key,
                conversationKeyVersion: version, senderId: Self.senderId,
                entities: entities, attachments: attachments)
        }

        XCTAssertThrowsError(try send(key: [UInt8](repeating: 0, count: 31))) { error in
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
            XCTAssertEqual(
                (error as? XChatError)?.message, "Invalid conversation key (expected 32 bytes)")
        }
        XCTAssertThrowsError(try send(version: "01")) { error in
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
        }
        XCTAssertThrowsError(
            try send(entities: [EntityDescriptor(start: 0, end: 5, type: .hashtag)])
        ) { error in
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
        }
        XCTAssertThrowsError(
            try send(attachments: [
                .media(
                    mediaHashKey: "h", width: 1, height: 1, filesizeBytes: 0,
                    filename: "f", mediaType: nil, durationMilliseconds: nil,
                    plaintextSHA256: nil)
            ])
        ) { error in
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
        }
        XCTAssertThrowsError(
            try send(attachments: [
                .post(restId: nil, postURL: nil)
            ])
        ) { error in
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
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
            XCTAssertEqual((error as? XChatError)?.kind, .invalidState)
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
