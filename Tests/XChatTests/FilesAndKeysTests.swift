import Testing

@testable import XChat

/// One encrypted file of a vector message, with the fields naming its hash
/// key, ciphertext, and plaintext.
struct MediaVectorCase: Sendable {
  var hashField: String
  var encryptedField: String
  var plaintextField: String
}

private let mediaVectorCases: [MediaVectorCase] = [
  MediaVectorCase(
    hashField: "media_first_hash_key", encryptedField: "media_first_encrypted_b64",
    plaintextField: "media_first_plaintext_b64"),
  MediaVectorCase(
    hashField: "media_second_hash_key", encryptedField: "media_second_encrypted_b64",
    plaintextField: "media_second_plaintext_b64"),
]

private let linkCardImageCases: [MediaVectorCase] = [
  MediaVectorCase(
    hashField: "media_banner_hash_key", encryptedField: "media_banner_encrypted_b64",
    plaintextField: "media_banner_plaintext_b64"),
  MediaVectorCase(
    hashField: "media_favicon_hash_key", encryptedField: "media_favicon_encrypted_b64",
    plaintextField: "media_favicon_plaintext_b64"),
]

/// Files resolved through the message that carries them, files under a
/// caller-held key, and the public-key registration payload.
struct FilesAndKeysTests {
  private static func messageKeyMap() throws -> [String: [UInt8]] {
    [
      TestVectors.string("message_key_conversation_key_version"): try Hex.decode(
        TestVectors.string("message_key_conversation_key_hex"))
    ]
  }

  // MARK: Received media

  /// Both files of the v1 message decrypt from the event, whole and in
  /// pieces, under keys derived from the message key and attachment ids.
  @Test(arguments: mediaVectorCases)
  func decryptsVectorMediaFromTheirMessage(file: MediaVectorCase) throws {
    let core = XChatCore()
    let keys = try Self.messageKeyMap()
    let event = TestVectors.string("event_message_key_b64")

    let hash = TestVectors.string(file.hashField)
    let encrypted = TestVectors.bytes(file.encryptedField)
    let plaintext = TestVectors.bytes(file.plaintextField)

    #expect(
      try core.decryptFile(
        encrypted, eventB64: event, conversationKeys: keys, mediaHashKey: hash)
        == plaintext, "\(file.hashField)")

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
    #expect(pieces == plaintext, "\(file.hashField)")
  }

  /// A link card's banner and favicon share the card's attachment key.
  @Test(arguments: linkCardImageCases)
  func decryptsLinkCardImages(file: MediaVectorCase) throws {
    let core = XChatCore()
    let keys = try Self.messageKeyMap()
    let event = TestVectors.string("event_link_card_b64")

    #expect(
      try core.decryptFile(
        TestVectors.bytes(file.encryptedField), eventB64: event,
        conversationKeys: keys,
        mediaHashKey: TestVectors.string(file.hashField))
        == TestVectors.bytes(file.plaintextField),
      "\(file.hashField)")
  }

  /// A v0 message's media decrypts under the conversation key.
  @Test func decryptsConversationKeyMedia() throws {
    let core = XChatCore()
    let keys = [
      TestVectors.string("event_conversation_key_version"):
        TestVectors.bytes("conversation_key_b64")
    ]
    #expect(
      try core.decryptFile(
        TestVectors.bytes("media_conversation_key_encrypted_b64"),
        eventB64: TestVectors.string("event_conversation_key_media_b64"),
        conversationKeys: keys,
        mediaHashKey: TestVectors.string("media_conversation_key_hash_key"))
        == TestVectors.bytes("media_conversation_key_plaintext_b64"))
  }

  /// The short-sender message's media resolves its own attachment key.
  @Test func decryptsShortMessageMedia() throws {
    let core = XChatCore()
    let keys = [
      TestVectors.string("message_key_short_conversation_key_version"):
        try Hex.decode(TestVectors.string("message_key_short_conversation_key_hex"))
    ]
    #expect(
      try core.decryptFile(
        TestVectors.bytes("media_short_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_short_b64"),
        conversationKeys: keys,
        mediaHashKey: TestVectors.string("media_short_hash_key"))
        == TestVectors.bytes("media_short_plaintext_b64"))
  }

  @Test func unencryptedEventMediaIsRejected() throws {
    let core = XChatCore()
    #expect(throws: XChatError.invalidInput(.notEncrypted(.message))) {
      try core.decryptFile(
        [1, 2, 3],
        eventB64: TestVectors.string("event_unencrypted_b64"),
        conversationKeys: [:],
        mediaHashKey: TestVectors.string("media_unencrypted_hash_key"))
    }
  }

  @Test func unknownMediaHashNamesTheMessagesHashes() throws {
    let core = XChatCore()
    #expect(
      throws: XChatError.invalidInput(
        .mediaHashKeyNotFound(
          "not-a-hash",
          available: [
            TestVectors.string("media_first_hash_key"),
            TestVectors.string("media_second_hash_key"),
          ]))
    ) {
      try core.decryptFile(
        [1, 2, 3], eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: try Self.messageKeyMap(), mediaHashKey: "not-a-hash")
    }
  }

  @Test func missingConversationKeyNamesTheVersion() throws {
    let core = XChatCore()
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(.message, version: "2002", available: ["1"]))
    ) {
      try core.decryptFile(
        TestVectors.bytes("media_first_encrypted_b64"),
        eventB64: TestVectors.string("event_message_key_b64"),
        conversationKeys: ["1": [UInt8](repeating: 0, count: 32)],
        mediaHashKey: TestVectors.string("media_first_hash_key"))
    }
  }

  // MARK: Outgoing files

  @Test func outgoingFileRoundTrip() throws {
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
    #expect(
      UInt64(encrypted.count) == encryptedFileSize(UInt64(file.count)))
    #expect(
      try core.decryptFile(
        encrypted, eventB64: payload.eventB64, conversationKeys: keys,
        mediaHashKey: mediaHashKey)
        == file)

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
    #expect(
      try core.decryptFile(
        streamed, eventB64: payload.eventB64, conversationKeys: keys,
        mediaHashKey: mediaHashKey)
        == file)

    // A hash that is not in the message is refused.
    #expect(
      throws: XChatError.invalidInput(.mediaHashKeyNotFound("nope", available: [mediaHashKey]))
    ) {
      try core.encryptFile(
        file, eventB64: payload.eventB64,
        conversationKey: TestVectors.bytes("conversation_key_b64"),
        conversationKeyVersion: "1001", mediaHashKey: "nope")
    }
  }

  @Test func editEventHasNoMedia() throws {
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

    #expect(throws: XChatError.invalidInput(.messageIsEdit(.message))) {
      try core.encryptFile(
        [1], eventB64: payload.eventB64,
        conversationKey: TestVectors.bytes("conversation_key_b64"),
        conversationKeyVersion: "1001", mediaHashKey: "h")
    }
  }

  // MARK: Files under a caller-held key

  @Test func fileWithKeyRoundTrip() throws {
    let core = XChatCore()
    let key = randomBytes(32)
    let file = (0..<2049).map { UInt8($0 % 251) }

    let encrypted = try core.encryptFileWithKey(file, key: key)
    #expect(try core.decryptFileWithKey(encrypted, key: key) == file)

    // A wrong key cannot open it: its first frame does not authenticate.
    let otherKey = randomBytes(32)
    #expect(
      throws: XChatError.decryption(.file(.authenticationFailed, mediaHashKey: nil))
    ) {
      try core.decryptFileWithKey(encrypted, key: otherKey)
    }

    for badKey in [[UInt8](repeating: 0, count: 31), [UInt8](repeating: 0, count: 33)] {
      #expect(throws: XChatError.invalidInput(.fileKeyLength(badKey.count))) {
        try core.encryptFileWithKey(file, key: badKey)
      }
      #expect(throws: XChatError.invalidInput(.fileKeyLength(badKey.count))) {
        try core.decryptFileWithKey(encrypted, key: badKey)
      }
    }
  }

  // MARK: Registration

  @Test func generateKeypairsRegistration() throws {
    let core = XChatCore()
    let payload = try core.generateKeypairs()
    let registration = payload.publicKey

    #expect(registration.registrationMethod == "CustomPin")
    let identitySPKI = try Base64.decodeStandard(registration.publicKey)
    let signingSPKI = try Base64.decodeStandard(registration.signingPublicKey)
    #expect(identitySPKI.count == 91)
    #expect(signingSPKI.count == 91)

    // Both halves of the binding verify.
    #expect(
      try verify(
        publicKey: signingSPKI,  // SPKI is accepted directly
        signature: try Base64.decodeStandard(
          registration.identityPublicKeySignature),
        payload: identitySPKI))
    let signingPublicKeySignature = try #require(registration.signingPublicKeySignature)
    #expect(
      try verify(
        publicKey: identitySPKI,
        signature: try Base64.decodeStandard(signingPublicKeySignature),
        payload: signingSPKI))

    // The fingerprint is URL-safe base64 SHA-256 of the identity SPKI.
    #expect(
      registration.publicKeyFingerprint
        == Base64.encodeURLSafe(sha256(identitySPKI)))

    // The loaded keys are the registration's keys in SEC1 form.
    let identitySEC1 = try core.identityPublicKey()
    #expect(try spkiDER(publicKey: identitySEC1) == identitySPKI)
    let publicKeys = try core.getPublicKeys()
    let signingSEC1Loaded = try core.signingPublicKey()
    let signingSEC1 = try #require(signingSEC1Loaded)
    #expect(
      try Base64.decodeStandard(publicKeys.identity) == identitySEC1)
    #expect(
      try Base64.decodeStandard(publicKeys.signing) == signingSEC1)

    let exported = try core.exportKeys()
    #expect(exported.identity.count == 32)
    #expect(exported.signing?.count == 32)

    try core.setPublicKeyVersion("123")
    #expect(core.publicKeyVersion == "123")
    #expect(throws: XChatError.invalidInput(.publicKeyVersion("0123"))) {
      try core.setPublicKeyVersion("0123")
    }
  }

  /// The fixture's registration binding: the signing key's signature over
  /// the identity key bytes as the API returns them (SEC1) verifies.
  @Test func vectorRegistrationBindingVerifies() throws {
    let identity = TestVectors.bytes("identity_public_b64")
    let signature = try Base64.decodeStandard(
      TestVectors.string("identity_public_key_signature_b64"))
    let signingPublic = TestVectors.bytes("signing_public_b64")

    #expect(
      try verify(
        publicKey: signingPublic, signature: signature, payload: identity))
  }
}
