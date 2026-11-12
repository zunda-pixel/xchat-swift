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
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
            XCTAssertEqual(
                (error as? XChatError)?.message,
                "the message is not encrypted, so neither is its media: "
                    + "use the downloaded bytes as they are")
        }
    }

    func testUnknownMediaHashNamesTheMessagesHashes() throws {
        let core = XChatCore()
        XCTAssertThrowsError(
            try core.decryptFile(
                [1, 2, 3], eventB64: TestVectors.string("event_message_key_b64"),
                conversationKeys: try Self.messageKeyMap(), mediaHashKey: "not-a-hash")
        ) { error in
            let message = (error as? XChatError)?.message ?? ""
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
            XCTAssertTrue(
                message.hasPrefix("media_hash_key 'not-a-hash' is not in the message, whose media hash keys are "),
                message)
            XCTAssertTrue(message.contains(TestVectors.string("media_first_hash_key")), message)
        }
    }

    func testMissingConversationKeyNamesTheVersion() throws {
        let core = XChatCore()
        XCTAssertThrowsError(
            try core.decryptFile(
                TestVectors.bytes("media_first_encrypted_b64"),
                eventB64: TestVectors.string("event_message_key_b64"),
                conversationKeys: ["1": [UInt8](repeating: 0, count: 32)],
                mediaHashKey: TestVectors.string("media_first_hash_key"))
        ) { error in
            let message = (error as? XChatError)?.message ?? ""
            XCTAssertEqual((error as? XChatError)?.kind, .decryption)
            XCTAssertTrue(
                message.hasPrefix(
                    "conversationKeys has no key for version '2002', which the message is "
                        + "encrypted under"),
                message)
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
            let message = (error as? XChatError)?.message ?? ""
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
            XCTAssertTrue(message.hasPrefix("media_hash_key 'nope' is not one of the message's files"), message)
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
            XCTAssertEqual(
                (error as? XChatError)?.message,
                "the message is an edit, and edits carry no media: "
                    + "pass the event of the message that was edited")
        }
    }

    // MARK: Files under a caller-held key

    func testFileWithKeyRoundTrip() throws {
        let core = XChatCore()
        let key = randomBytes(32)
        let file = (0..<2049).map { UInt8($0 % 251) }

        let encrypted = try core.encryptFileWithKey(file, key: key)
        XCTAssertEqual(try core.decryptFileWithKey(encrypted, key: key), file)

        // A wrong key cannot open it, and the error says what to pass.
        let otherKey = randomBytes(32)
        XCTAssertThrowsError(try core.decryptFileWithKey(encrypted, key: otherKey)) { error in
            let message = (error as? XChatError)?.message ?? ""
            XCTAssertEqual((error as? XChatError)?.kind, .decryption)
            XCTAssertTrue(
                message.hasPrefix(
                    "the bytes are not a complete file encrypted under this key"),
                message)
        }

        for badKey in [[UInt8](repeating: 0, count: 31), [UInt8](repeating: 0, count: 33)] {
            XCTAssertThrowsError(try core.encryptFileWithKey(file, key: badKey)) { error in
                XCTAssertEqual(
                    (error as? XChatError)?.message,
                    "Invalid key (expected 32 bytes, got \(badKey.count))")
            }
            XCTAssertThrowsError(try core.decryptFileWithKey(encrypted, key: badKey))
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

        // The loaded keys are the registration's keys in SEC1 form.
        let identitySEC1 = try core.identityPublicKey()
        XCTAssertEqual(try spkiDER(publicKey: identitySEC1), identitySPKI)
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
            XCTAssertEqual((error as? XChatError)?.kind, .invalidInput)
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
