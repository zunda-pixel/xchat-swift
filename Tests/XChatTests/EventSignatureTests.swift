import XCTest

@testable import XChat

/// The signature payload layouts and verification, against signatures the
/// reference produced: a v7 message, a v10 (per-message-key) message, and a
/// v7 conversation-key change.
final class EventSignatureTests: XCTestCase {
    private static let signingKey = SigningKey(
        publicKeyVersion: TestVectors.string("event_signing_key_version"),
        publicKey: TestVectors.string("signing_public_b64"))

    private func decodeEvent(_ field: String) throws -> MessageEvent {
        var reader = ThriftReader(TestVectors.bytes(field))
        let event = try MessageEvent.read(&reader)
        XCTAssertTrue(reader.isAtEnd)
        return event
    }

    private func detail(of event: MessageEvent) throws -> MessageEventDetail {
        try XCTUnwrap(event.detail)
    }

    // MARK: Vector signatures

    func testVectorConversationKeyMessageSignatureVerifies() throws {
        let event = try decodeEvent("event_message_b64")
        XCTAssertEqual(signatureVersion(of: event), 7)
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [Self.signingKey]),
            .verified)
    }

    /// The v1 message signs at v10, covering `contents_encryption_version`.
    func testVectorMessageKeySignatureVerifies() throws {
        let event = try decodeEvent("event_message_key_b64")
        XCTAssertEqual(signatureVersion(of: event), 10)
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [Self.signingKey]),
            .verified)
    }

    /// A key change from v6 on signs the plaintext conversation key, so the
    /// caller (or the SDK) supplies its unpadded base64.
    func testVectorKeyChangeSignatureVerifies() throws {
        let event = try decodeEvent("event_key_change_b64")
        let keyB64 = Base64.encodeStandard(TestVectors.bytes("conversation_key_b64"))
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [Self.signingKey],
                plaintextConversationKeyB64: keyB64),
            .verified)

        // Without the key the payload cannot be rebuilt.
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [Self.signingKey]),
            .unverifiable)
    }

    func testWrongKeyFails() throws {
        let event = try decodeEvent("event_message_b64")
        let otherKey = SigningKey(
            publicKeyVersion: Self.signingKey.publicKeyVersion,
            publicKey: Base64.encodeStandard(generateKeyPair().publicKey))
        guard
            case .failed(let reason) = checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [otherKey])
        else {
            return XCTFail("expected a signature mismatch")
        }
        XCTAssertTrue(reason.hasPrefix("ECDSA mismatch"), reason)

        // A key known under a different version leaves the event unverifiable.
        let unknownVersion = SigningKey(
            publicKeyVersion: "99", publicKey: Self.signingKey.publicKey)
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [unknownVersion]),
            .unverifiable)
    }

    func testTamperedEventFails() throws {
        var event = try decodeEvent("event_message_b64")
        event.messageId = "2c2a1d32-0000-0000-0000-000000000000"
        guard
            case .failed = checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [Self.signingKey])
        else {
            return XCTFail("expected a signature mismatch")
        }
    }

    // MARK: Payload layouts

    private func messageEvent(
        messageId: String = "m",
        senderId: String = "s",
        conversationId: String? = "c",
        contents: [UInt8] = [1],
        keyVersion: String? = "9",
        contentsVersion: Int16? = nil,
        signatureVersion version: String?
    ) -> MessageEvent {
        var event = MessageEvent()
        event.messageId = messageId
        event.senderId = senderId
        event.conversationId = conversationId
        var signature = MessageEventSignature()
        signature.signature = "AQ"
        signature.signatureVersion = version
        event.messageEventSignature = signature
        event.detail = .messageCreate(
            MessageCreateEvent(
                contents: contents,
                conversationKeyVersion: keyVersion,
                shouldNotify: nil,
                ttlMilliseconds: nil,
                deliveredAtMilliseconds: nil,
                isPendingPublicKey: nil,
                isMessageRequest: nil,
                contentsEncryptionVersion: contentsVersion))
        return event
    }

    func testMessagePayloadLayouts() throws {
        // v7: the contents' unpadded base64 and the integer key version.
        let v7 = messageEvent(signatureVersion: "7")
        XCTAssertEqual(
            eventSignaturePayload(event: v7, detail: try detail(of: v7)),
            "MessageCreateEvent,m,s,c,9,\(Base64.encodeStandard([1]))")

        // v10 adds contents_encryption_version, "null" when unset, and both
        // v9 and v10 bind signature_version into the payload.
        let v10 = messageEvent(contentsVersion: 1, signatureVersion: "10")
        XCTAssertEqual(
            eventSignaturePayload(event: v10, detail: try detail(of: v10)),
            "MessageCreateEvent,m,s,c,9,\(Base64.encodeStandard([1])),1,signature_version=10")
        let v10Unset = messageEvent(signatureVersion: "10")
        XCTAssertEqual(
            eventSignaturePayload(event: v10Unset, detail: try detail(of: v10Unset)),
            "MessageCreateEvent,m,s,c,9,\(Base64.encodeStandard([1])),null,signature_version=10")

        // v9 binds the version but does not cover contents_encryption_version.
        let v9 = messageEvent(contentsVersion: 1, signatureVersion: "9")
        XCTAssertEqual(
            eventSignaturePayload(event: v9, detail: try detail(of: v9)),
            "MessageCreateEvent,m,s,c,9,\(Base64.encodeStandard([1])),signature_version=9")

        // An absent conversation id drops the component.
        let noConversation = messageEvent(conversationId: nil, signatureVersion: "7")
        XCTAssertEqual(
            eventSignaturePayload(event: noConversation, detail: try detail(of: noConversation)),
            "MessageCreateEvent,m,s,9,\(Base64.encodeStandard([1]))")

        // Below the floor there is no verifiable layout.
        let v1 = messageEvent(signatureVersion: "1")
        XCTAssertNil(eventSignaturePayload(event: v1, detail: try detail(of: v1)))
        // A missing version has none either.
        let unversioned = messageEvent(signatureVersion: nil)
        XCTAssertNil(eventSignaturePayload(event: unversioned, detail: try detail(of: unversioned)))
    }

    func testKeyChangePayloadLayouts() throws {
        func keyChange(
            version: String, participants: [ConversationParticipantKey]
        ) -> MessageEvent {
            var event = MessageEvent()
            event.messageId = "m"
            event.senderId = "s"
            event.conversationId = "c"
            var signature = MessageEventSignature()
            signature.signatureVersion = version
            event.messageEventSignature = signature
            event.detail = .conversationKeyChange(
                ConversationKeyChangeEvent(
                    conversationKeyVersion: "1001",
                    conversationParticipantKeys: participants,
                    forKeyRotation: nil))
            return event
        }

        // v6+: the plaintext conversation key's unpadded base64.
        let modern = keyChange(
            version: "7",
            participants: [
                ConversationParticipantKey(
                    userId: "u1", encryptedConversationKey: "e1", publicKeyVersion: "1")
            ])
        XCTAssertEqual(
            eventSignaturePayload(
                event: modern, detail: try detail(of: modern), plaintextConversationKeyB64: "AAAA"),
            "ConversationKeyChangeEvent,m,s,c,1001,AAAA")

        // Pre-v6: the participant triplets, fields an entry lacks omitted.
        let legacy = keyChange(
            version: "5",
            participants: [
                ConversationParticipantKey(
                    userId: "u1", encryptedConversationKey: "e1", publicKeyVersion: "1"),
                ConversationParticipantKey(
                    userId: "u2", encryptedConversationKey: nil, publicKeyVersion: nil),
            ])
        XCTAssertEqual(
            eventSignaturePayload(event: legacy, detail: try detail(of: legacy)),
            "ConversationKeyChangeEvent,m,s,c,1001,u1,e1,1,u2")

        // A non-integer key version has no payload.
        var notAnInteger = modern
        notAnInteger.detail = .conversationKeyChange(
            ConversationKeyChangeEvent(
                conversationKeyVersion: "later",
                conversationParticipantKeys: nil,
                forKeyRotation: nil))
        XCTAssertNil(
            eventSignaturePayload(event: notAnInteger, detail: try detail(of: notAnInteger)))
    }

    func testDeleteAndUnmodelledPayloads() throws {
        var deletion = MessageEvent()
        deletion.messageId = "m"
        deletion.senderId = "s"
        deletion.conversationId = "c"
        var signature = MessageEventSignature()
        signature.signatureVersion = "7"
        deletion.messageEventSignature = signature
        deletion.detail = .messageDelete(
            MessageDeleteEvent(sequenceIds: ["5", "6"], deleteMessageAction: 2))

        XCTAssertEqual(
            eventSignaturePayload(event: deletion, detail: try detail(of: deletion)),
            "MessageDeleteEvent,m,s,c,2,5,6")

        var conversationDeletion = deletion
        conversationDeletion.detail = .conversationDelete(
            ConversationDeleteEvent(conversationId: "c"))
        XCTAssertEqual(
            eventSignaturePayload(
                event: conversationDeletion, detail: try detail(of: conversationDeletion)),
            "ConversationDeleteEvent,m,s,c")

        // Typing and unmodelled variants carry no rebuilt payload.
        var typing = deletion
        typing.detail = .messageTyping(MessageTypingEvent(conversationId: "c"))
        XCTAssertNil(eventSignaturePayload(event: typing, detail: try detail(of: typing)))
        var unsupported = deletion
        unsupported.detail = .unsupported(fieldId: 12)
        XCTAssertNil(
            eventSignaturePayload(event: unsupported, detail: try detail(of: unsupported)))
    }

    /// A comma in any component makes the payload ambiguous, so it is
    /// refused when building and unverifiable when checking.
    func testCommaInComponentIsRefused() throws {
        let event = messageEvent(messageId: "m,1", signatureVersion: "7")
        XCTAssertThrowsError(
            try signEventSignature(
                signingPrivateKey: generateKeyPair().privateKey,
                publicKeyVersion: "1",
                messageId: "m,1",
                senderId: "s",
                conversationId: "c",
                signatureVersion: 7,
                detail: try detail(of: event))
        ) { error in
            let error = error as? XChatError
            XCTAssertEqual(error?.kind, .invalidInput)
            XCTAssertEqual(
                error?.message, "Signature payload contains comma-separated component")
        }
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: try detail(of: event), signingKeys: [Self.signingKey]),
            .unverifiable)
    }

    /// The fixture's own v10 payload and signature: the payload names the
    /// signature version, covers contents_encryption_version, and the SPKI
    /// public key verifies it.
    func testV10PayloadFixtureVerifies() throws {
        let publicKey = try Base64.decodeStandard(
            TestVectors.string("signature_v10_cev1_public_key_b64"))
        XCTAssertEqual(publicKey.count, 91)
        let signature = try Base64.decodeStandard(TestVectors.string("signature_v10_cev1_b64"))

        XCTAssertTrue(
            try verify(
                publicKey: publicKey, signature: signature,
                payload: Array(TestVectors.string("payload_message_v10_cev1").utf8)))
        // The same signature does not verify the layout without
        // contents_encryption_version.
        XCTAssertFalse(
            try verify(
                publicKey: publicKey, signature: signature,
                payload: Array(TestVectors.string("payload_message_v10").utf8)))
    }

    // MARK: Version bounds

    func testVersionBounds() throws {
        let tooOld = messageEvent(signatureVersion: "1")
        XCTAssertEqual(
            checkEventSignature(
                event: tooOld, detail: try detail(of: tooOld), signingKeys: [Self.signingKey]),
            .failed("signature_version 1 is no longer accepted (minimum: 2)"))

        let tooNew = messageEvent(signatureVersion: "12")
        XCTAssertEqual(
            checkEventSignature(
                event: tooNew, detail: try detail(of: tooNew), signingKeys: [Self.signingKey]),
            .failed("signature_version 12 is not supported (maximum: 11)"))

        let unversioned = messageEvent(signatureVersion: nil)
        XCTAssertEqual(
            checkEventSignature(
                event: unversioned, detail: try detail(of: unversioned),
                signingKeys: [Self.signingKey]),
            .failed("signature_version is missing or not an integer"))
    }

    // MARK: Signing round trips

    func testMessageSignAndVerifyRoundTrip() throws {
        let keypair = generateKeyPair()
        let signingKey = SigningKey(
            publicKeyVersion: "5", publicKey: Base64.encodeStandard(keypair.publicKey))
        let detail = MessageEventDetail.messageCreate(
            MessageCreateEvent(
                contents: [1, 2, 3],
                conversationKeyVersion: "1001",
                shouldNotify: true,
                ttlMilliseconds: nil,
                deliveredAtMilliseconds: nil,
                isPendingPublicKey: nil,
                isMessageRequest: nil,
                contentsEncryptionVersion: 1))

        let (signature, payload) = try signEventSignature(
            signingPrivateKey: keypair.privateKey,
            publicKeyVersion: "5",
            messageId: "m",
            senderId: "s",
            conversationId: "s:t",
            signatureVersion: 10,
            detail: detail)
        XCTAssertEqual(signature.signatureVersion, "10")
        XCTAssertEqual(signature.publicKeyVersion, "5")
        XCTAssertEqual(signature.signingPublicKey, Base64.encodeStandard(keypair.publicKey))

        var event = MessageEvent()
        event.messageId = "m"
        event.senderId = "s"
        event.conversationId = "s:t"
        event.messageEventSignature = signature
        XCTAssertEqual(
            checkEventSignature(event: event, detail: detail, signingKeys: [signingKey]),
            .verified)
        // The signed bytes are exactly the ones a verifier rebuilds.
        XCTAssertEqual(payload, eventSignaturePayload(event: event, detail: detail))
    }

    func testKeyChangeSignAndVerifyRoundTrip() throws {
        let keypair = generateKeyPair()
        let signingKey = SigningKey(
            publicKeyVersion: "2", publicKey: Base64.encodeStandard(keypair.publicKey))
        let detail = MessageEventDetail.conversationKeyChange(
            ConversationKeyChangeEvent(
                conversationKeyVersion: "1001",
                conversationParticipantKeys: [
                    ConversationParticipantKey(
                        userId: "u", encryptedConversationKey: "e", publicKeyVersion: "2")
                ],
                forKeyRotation: nil))
        let keyB64 = Base64.encodeStandard(TestVectors.bytes("conversation_key_b64"))
        let (signature, _) = try signEventSignature(
            signingPrivateKey: keypair.privateKey,
            publicKeyVersion: "2",
            messageId: "m",
            senderId: "s",
            conversationId: "s:t",
            signatureVersion: 7,
            detail: detail,
            plaintextConversationKeyB64: keyB64)

        var event = MessageEvent()
        event.messageId = "m"
        event.senderId = "s"
        event.conversationId = "s:t"
        event.messageEventSignature = signature
        XCTAssertEqual(
            checkEventSignature(
                event: event, detail: detail, signingKeys: [signingKey],
                plaintextConversationKeyB64: keyB64),
            .verified)
        // With the wrong key the payload differs and verification fails.
        let wrongKey = Base64.encodeStandard([UInt8](repeating: 7, count: 32))
        guard
            case .failed = checkEventSignature(
                event: event, detail: detail, signingKeys: [signingKey],
                plaintextConversationKeyB64: wrongKey)
        else {
            return XCTFail("expected a signature mismatch")
        }
    }
}
