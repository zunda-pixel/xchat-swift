import Testing

@testable import XChat

/// The errors `decryptEvent` and `decryptEvents` report: which key does not
/// open a message, malformed Thrift in an event or in a message's
/// contents, signatures that are rejected and why, and events that cannot
/// be verified.
struct DecryptEventErrorTests {
  private static let senderId = TestVectors.string("event_sender_id")
  private static let signingKeyVersion = TestVectors.string("event_signing_key_version")
  private static let conversationKeys = ["1001": TestVectors.bytes("conversation_key_b64")]

  /// The fixture's signing key, given for `userId` without an identity-key
  /// binding.
  private static func signingKey(userId: String = senderId) -> SigningKeyEntry {
    SigningKeyEntry(
      userId: userId, publicKeyVersion: signingKeyVersion,
      publicKey: TestVectors.string("signing_public_b64"))
  }

  // MARK: Keys and contents

  /// Without a key for the message's version, the versions keys were given
  /// for are listed in numeric order.
  @Test func missingConversationKeyListsTheVersionsInNumericOrder() {
    let key = [UInt8](repeating: 0, count: 32)
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(.message, version: "1001", available: ["9", "10", "100"]))
    ) {
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["10": key, "9": key, "100": key],
        signingKeys: [Self.signingKey()])
    }
  }

  /// A key that does not open the message's contents is named with the
  /// version it was given for, whether it is another key or the wrong
  /// length.
  @Test(arguments: [
    (32, XChatError.ContentsFailure.authenticationFailed),
    (31, .keyLength(31)),
  ])
  func keyThatDoesNotOpenTheMessageNamesItsVersion(
    keyLength: Int, failure: XChatError.ContentsFailure
  ) {
    #expect(
      throws: XChatError.decryption(
        .messageContents(.message, failure, key: .conversationKey(version: "1001")))
    ) {
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"),
        conversationKeys: ["1001": [UInt8](repeating: 1, count: keyLength)],
        signingKeys: [Self.signingKey()])
    }
  }

  /// Contents shorter than a nonce and tag are reported as too short to be
  /// encrypted contents, named with the message and its key's version.
  @Test func contentsTooShortToBeEncrypted() throws {
    // Replacing the contents breaks the signature, which only the policy
    // would reject.
    let short = try replacingContents(TestVectors.string("event_message_b64"), with: [1, 2, 3])
    #expect(
      throws: XChatError.decryption(
        .messageContents(.message, .ciphertextTooShort, key: .conversationKey(version: "1001")))
    ) {
      try XChatCore(rejectUnverified: false).decryptEvent(
        short, conversationKeys: Self.conversationKeys)
    }
  }

  // MARK: Malformed Thrift

  /// Malformed Thrift says what was being read: the event, or a message's
  /// contents, whether they decrypted or were sent unencrypted.
  @Test func malformedThriftNamesWhatWasRead() throws {
    #expect(throws: XChatError.parse(.event(.thrift(.unexpectedEnd))), "the event") {
      try XChatCore().decryptEvent(Base64.encodeStandard([0x0b, 0x00]))
    }

    // Contents that decrypt to a truncated struct, in an unsigned event.
    let key = TestVectors.bytes("conversation_key_b64")
    let event = MessageEvent(
      sequenceId: "1", messageId: "m", senderId: "1111", conversationId: "1111:2222",
      detail: .messageCreate(
        MessageCreateEvent(
          contents: try encryptMessage(key: key, plaintext: [0x0c]),
          conversationKeyVersion: "1001")))
    #expect(
      throws: XChatError.parse(.messageContents(.message, .unexpectedEnd)), "decrypted contents"
    ) {
      try XChatCore(rejectUnverified: false).decryptEvent(
        encodedEvent(event), conversationKeys: ["1001": key])
    }

    // The same struct sent as an unencrypted message's contents.
    let unencrypted = MessageEvent(
      sequenceId: "1", messageId: "m", senderId: "1111", conversationId: "1111:2222",
      detail: .messageCreate(MessageCreateEvent(contents: [0x0c])))
    #expect(
      throws: XChatError.parse(.messageContents(.message, .unexpectedEnd)),
      "unencrypted contents"
    ) {
      try XChatCore(rejectUnverified: false).decryptEvent(encodedEvent(unencrypted))
    }
  }

  /// An event reports what in it is malformed: a field of another wire
  /// type than the schema's, a string that is not UTF-8, and a list or a
  /// map of other types than its field's.
  @Test(arguments: malformedEvents)
  func malformedEventNamesWhatIsWrong(
    name: String, eventB64: String, failure: XChatError.ThriftFailure
  ) {
    #expect(throws: XChatError.parse(.event(.thrift(failure)))) {
      try XChatCore().decryptEvent(eventB64)
    }
  }

  /// A message's contents report what in them is malformed: a string that
  /// is not UTF-8, a list or a map of other types than its field's, and an
  /// attachment of the message or of the message its reply preview shows
  /// that sets none of its variants.
  @Test(arguments: malformedContents)
  func malformedContentsNameWhatIsWrong(
    name: String, eventB64: String, failure: XChatError.ThriftFailure
  ) {
    #expect(throws: XChatError.parse(.messageContents(.message, failure))) {
      try XChatCore(rejectUnverified: false).decryptEvent(eventB64)
    }
  }

  // MARK: Rejected signatures

  /// Why a message's signature is checked and fails.
  enum MessageSignatureRejection: CaseIterable {
    /// The sender's key at the event's version is another P-256 key.
    case otherSigningKey
    /// The sender's key at the event's version is not a P-256 point.
    case signingKeyThatIsNoPoint
    /// The event's signature is 3 bytes.
    case shortSignature
  }

  /// A signature that is checked and fails says why, for a message thrown
  /// by `decryptEvent`.
  @Test(arguments: MessageSignatureRejection.allCases)
  func rejectedMessageSignaturesSayWhy(rejection: MessageSignatureRejection) throws {
    var eventB64 = TestVectors.string("event_message_b64")
    let signingKey: SigningKeyEntry
    let failure: XChatError.SignatureFailure
    switch rejection {
    case .otherSigningKey:
      signingKey = SigningKeyEntry(
        userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion,
        publicKey: Base64.encodeStandard(generateKeyPair().publicKey))
      failure = .mismatch(senderId: Self.senderId, keyVersion: Self.signingKeyVersion)
    case .signingKeyThatIsNoPoint:
      signingKey = SigningKeyEntry(
        userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion,
        publicKey: signingKeyThatIsNoPoint)
      failure = .invalidSigningPublicKey(
        senderId: Self.senderId, keyVersion: Self.signingKeyVersion)
    case .shortSignature:
      signingKey = Self.signingKey()
      eventB64 = try rewritingEvent(eventB64) {
        $0.messageEventSignature?.signature = Base64.encodeStandard([1, 2, 3])
      }
      failure = .malformedSignature
    }
    #expect(throws: XChatError.verification(.rejected(.message, failure))) {
      try XChatCore().decryptEvent(
        eventB64, conversationKeys: Self.conversationKeys, signingKeys: [signingKey])
    }
  }

  /// A key change's signature that is checked and fails says why too,
  /// collected by `decryptEvents` at the event's index.
  @Test func rejectedKeyChangeSignatureSaysWhy() throws {
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: TestVectors.bytes("identity_private_b64"),
      signingPrivateKey: TestVectors.bytes("signing_private_b64"),
      publicKeyVersion: TestVectors.string("event_recipient_key_version"))
    let batch = core.decryptEvents(
      [TestVectors.string("event_key_change_b64")],
      signingKeys: [
        SigningKeyEntry(
          userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion,
          publicKey: signingKeyThatIsNoPoint)
      ])
    #expect(
      batch.errors == [
        0: .verification(
          .rejected(
            .keyChange,
            .invalidSigningPublicKey(senderId: Self.senderId, keyVersion: Self.signingKeyVersion)))
      ])
  }

  /// A key change signed at signature version 6 or later, as the fixture's
  /// is, signs its conversation key in plaintext, so on a core that cannot
  /// decrypt that key from the event, a wrong key given for its version is
  /// a mismatch under the right signing key.
  @Test func aKeyChangeCheckedUnderAWrongConversationKeyIsAMismatch() {
    #expect(
      throws: XChatError.verification(
        .rejected(
          .keyChange, .mismatch(senderId: Self.senderId, keyVersion: Self.signingKeyVersion)))
    ) {
      try XChatCore().decryptEvent(
        TestVectors.string("event_key_change_b64"),
        conversationKeys: ["1001": [UInt8](repeating: 7, count: 32)],
        signingKeys: [Self.signingKey()])
    }
  }

  /// The same key change, on a core that cannot decrypt its conversation
  /// key and with no key given for its version (none, or only another
  /// version's), leaves no payload to check: it is unverifiable under the
  /// right signing key, from `decryptEvent` and `decryptEvents` alike.
  @Test(arguments: [[:], ["1000": TestVectors.bytes("conversation_key_b64")]])
  func aKeyChangeWhoseConversationKeyIsNeitherDecryptedNorGivenIsUnverifiable(
    conversationKeys: [String: [UInt8]]
  ) {
    let keyChange = TestVectors.string("event_key_change_b64")
    let unverifiable = XChatError.verification(.unverifiable(.keyChange))
    #expect(throws: unverifiable) {
      try XChatCore().decryptEvent(
        keyChange, conversationKeys: conversationKeys, signingKeys: [Self.signingKey()])
    }
    let batch = XChatCore().decryptEvents(
      [keyChange], conversationKeys: conversationKeys, signingKeys: [Self.signingKey()])
    #expect(batch.errors == [0: unverifiable])
  }

  /// The fixture's message with `signature` as its signature, decrypted
  /// with `signingKey` as the only signing key.
  private func decrypt(signature: String, signingKey: SigningKeyEntry) throws {
    var event = try XChatCore().parseEvent(TestVectors.string("event_message_b64"))
    event.messageEventSignature?.signature = signature
    _ = try XChatCore().decryptEvent(
      encodedEvent(event), conversationKeys: Self.conversationKeys, signingKeys: [signingKey])
  }

  /// When both the signing key and the signature are malformed, the key is
  /// reported, however each is malformed: the key is checked before the
  /// signature.
  @Test(arguments: malformedSigningKeys, malformedSignatures)
  func aMalformedSigningKeyIsReportedBeforeAMalformedSignature(
    signingKey: String, signature: String
  ) {
    #expect(
      throws: XChatError.verification(
        .rejected(
          .message,
          .invalidSigningPublicKey(senderId: Self.senderId, keyVersion: Self.signingKeyVersion)))
    ) {
      try decrypt(
        signature: signature,
        signingKey: SigningKeyEntry(
          userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion, publicKey: signingKey))
    }
  }

  /// With the signing key right, each of the signatures above is
  /// malformed.
  @Test(arguments: malformedSignatures)
  func aMalformedSignatureIsReportedUnderTheRightKey(signature: String) {
    #expect(throws: XChatError.verification(.rejected(.message, .malformedSignature))) {
      try decrypt(signature: signature, signingKey: Self.signingKey())
    }
  }

  /// A signing key that is not a P-256 public key is rejected as such, with
  /// its key version, only when it is given without an identity-key
  /// binding. Given with one, it fails the binding, which needs the key's
  /// SPKI, so it is not used and the event is unverifiable, whether or not
  /// the key is base64.
  @Test(arguments: malformedSigningKeys)
  func aMalformedSigningKeyWithABindingIsNotUsed(signingKey: String) throws {
    let identitySignature = try sign(
      privateKey: TestVectors.bytes("identity_private_b64"),
      payload: try spkiDER(publicKey: TestVectors.bytes("signing_public_b64")))
    func decryptMessage(signingKey: SigningKeyEntry) throws {
      _ = try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"), conversationKeys: Self.conversationKeys,
        signingKeys: [signingKey])
    }

    #expect(
      throws: XChatError.verification(
        .rejected(
          .message,
          .invalidSigningPublicKey(senderId: Self.senderId, keyVersion: Self.signingKeyVersion))),
      "without a binding"
    ) {
      try decryptMessage(
        signingKey: SigningKeyEntry(
          userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion, publicKey: signingKey))
    }
    #expect(throws: XChatError.verification(.unverifiable(.message)), "with a binding") {
      try decryptMessage(
        signingKey: SigningKeyEntry(
          userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion, publicKey: signingKey,
          identityPublicKey: TestVectors.string("identity_public_b64"),
          signingPublicKeySignature: Base64.encodeStandard(identitySignature)))
    }
  }

  // MARK: Unverifiable events

  /// With the right key, an event the signed payload cannot be rebuilt
  /// from, here for lack of its message id, cannot be checked either, so
  /// by default it is rejected as unverifiable before it is opened. With
  /// the policy off, a v1 message, whose key derives from that id, is
  /// opened and fails as missing it.
  @Test func aMessageWithoutItsMessageIdIsUnverifiable() throws {
    let withoutMessageId = try rewritingEvent(TestVectors.string("event_message_b64")) {
      $0.messageId = nil
    }
    #expect(throws: XChatError.verification(.unverifiable(.message)), "v0") {
      try XChatCore().decryptEvent(
        withoutMessageId, conversationKeys: Self.conversationKeys,
        signingKeys: [Self.signingKey()])
    }

    let v1WithoutMessageId = try rewritingEvent(TestVectors.string("event_message_key_b64")) {
      $0.messageId = nil
    }
    let v1Keys = [
      TestVectors.string("message_key_conversation_key_version"): try Hex.decode(
        TestVectors.string("message_key_conversation_key_hex"))
    ]
    let v1SigningKey = Self.signingKey(userId: TestVectors.string("message_key_sender_id"))
    #expect(throws: XChatError.verification(.unverifiable(.message)), "v1") {
      try XChatCore().decryptEvent(
        v1WithoutMessageId, conversationKeys: v1Keys, signingKeys: [v1SigningKey])
    }
    #expect(
      throws: XChatError.decryption(.missingSenderOrMessageId(.message)),
      "v1, with the policy off"
    ) {
      try XChatCore(rejectUnverified: false).decryptEvent(
        v1WithoutMessageId, conversationKeys: v1Keys, signingKeys: [v1SigningKey])
    }
  }

  /// An identity-key binding of a signing key that cannot be checked.
  enum UncheckableBinding: CaseIterable {
    /// The right signature, without the identity key it is checked under.
    case withoutIdentityKey
    /// A signature that is not base64.
    case signatureNotBase64
  }

  /// A signing key whose identity-key binding cannot be checked is not
  /// used, as one whose binding does not verify is not, so an event only it
  /// could verify is unverifiable.
  @Test(arguments: UncheckableBinding.allCases)
  func aSigningKeyWhoseBindingCannotBeCheckedIsNotUsed(binding: UncheckableBinding) throws {
    let signingKey: SigningKeyEntry
    switch binding {
    case .withoutIdentityKey:
      let signature = try sign(
        privateKey: TestVectors.bytes("identity_private_b64"),
        payload: try spkiDER(publicKey: TestVectors.bytes("signing_public_b64")))
      signingKey = SigningKeyEntry(
        userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion,
        publicKey: TestVectors.string("signing_public_b64"),
        signingPublicKeySignature: Base64.encodeStandard(signature))
    case .signatureNotBase64:
      signingKey = SigningKeyEntry(
        userId: Self.senderId, publicKeyVersion: Self.signingKeyVersion,
        publicKey: TestVectors.string("signing_public_b64"),
        identityPublicKey: TestVectors.string("identity_public_b64"),
        signingPublicKeySignature: "not base64!")
    }
    #expect(throws: XChatError.verification(.unverifiable(.message))) {
      try XChatCore().decryptEvent(
        TestVectors.string("event_message_b64"), conversationKeys: Self.conversationKeys,
        signingKeys: [signingKey])
    }
  }

  /// A key change signs its conversation-key version as an integer, so a
  /// version that is not one leaves no payload to check: the event is
  /// unverifiable, not a mismatch, though its signing key and conversation
  /// key are given.
  @Test func keyChangeWhoseVersionIsNotAnIntegerIsUnverifiable() throws {
    let encoded = try rewritingEvent(TestVectors.string("event_key_change_b64")) { event in
      guard case .conversationKeyChange(var change)? = event.detail else { return }
      change.conversationKeyVersion = "v1001"
      event.detail = .conversationKeyChange(change)
    }
    #expect(throws: XChatError.verification(.unverifiable(.keyChange))) {
      try XChatCore().decryptEvent(
        encoded, conversationKeys: ["v1001": TestVectors.bytes("conversation_key_b64")],
        signingKeys: [Self.signingKey()])
    }
  }

  /// An unencrypted message is unverifiable even when its signature holds
  /// under the sender's key: it is rejected by default, and marked
  /// unverified with the policy off.
  @Test func unencryptedMessageIsNeverVerified() throws {
    var event = try XChatCore().parseEvent(TestVectors.string("event_unencrypted_b64"))
    let detail = try #require(event.detail)
    let senderId = try #require(event.senderId)
    event.messageEventSignature =
      try signEventSignature(
        signingPrivateKey: TestVectors.bytes("signing_private_b64"),
        publicKeyVersion: Self.signingKeyVersion, messageId: try #require(event.messageId),
        senderId: senderId, conversationId: event.conversationId,
        signatureVersion: currentSignatureVersion, detail: detail
      ).signature
    #expect(
      checkEventSignature(
        event: event, detail: detail,
        signingKeys: [
          SigningKey(
            publicKeyVersion: Self.signingKeyVersion,
            publicKey: TestVectors.string("signing_public_b64"))
        ]) == .verified)

    let signed = encodedEvent(event)
    #expect(throws: XChatError.verification(.unverifiable(.message))) {
      try XChatCore().decryptEvent(signed, signingKeys: [Self.signingKey(userId: senderId)])
    }
    let decrypted = try XChatCore(rejectUnverified: false).decryptEvent(
      signed, signingKeys: [Self.signingKey(userId: senderId)])
    guard case .message(let message) = decrypted else {
      Issue.record("expected a message event, got \(decrypted)")
      return
    }
    #expect(!message.verified)
  }

  // MARK: Batches

  /// A batch holds only XChatError values; an error of another type would
  /// be kept as its description rather than dropped.
  @Test func otherErrorsBecomeUnexpectedWithTheirDescription() {
    struct Other: Error {}
    #expect(XChatError(Other()) == .internalError(.unexpected("Other()")))
    #expect(XChatError(XChatError.invalidState(.keysNotLoaded)) == .invalidState(.keysNotLoaded))
  }
}

/// A signing key that is base64 but not a P-256 point.
private let signingKeyThatIsNoPoint = Base64.encodeStandard(
  [0x04] + [UInt8](repeating: 0, count: 64))

/// Signing keys that are not P-256 public keys: not base64, and not a
/// point.
private let malformedSigningKeys = ["not base64!", signingKeyThatIsNoPoint]

/// Signatures that are not 64 bytes: too short, too long, and not base64.
private let malformedSignatures = [
  Base64.encodeStandard([1, 2, 3]),
  Base64.encodeStandard([UInt8](repeating: 1, count: 65)),
  "not base64!",
]

/// The bytes `write` writes.
private func encoded(_ write: (inout ThriftWriter) -> Void) -> [UInt8] {
  var writer = ThriftWriter()
  write(&writer)
  return writer.data
}

/// `event` as base64 Thrift.
private func encodedEvent(_ event: MessageEvent) -> String {
  var writer = ThriftWriter()
  event.write(to: &writer)
  return Base64.encodeStandard(writer.data)
}

/// A message-delete event, whose fields are written by `write`.
private func deleteEvent(_ write: (inout ThriftWriter) -> Void) -> String {
  Base64.encodeStandard(
    encoded { writer in
      writer.writeFieldBegin(id: 7, type: .structure)  // detail
      writer.writeFieldBegin(id: 7, type: .structure)  // messageDeleteEvent
      write(&writer)
      writer.writeFieldStop()  // end the delete event
      writer.writeFieldStop()  // end the detail union
      writer.writeFieldStop()  // end the event
    })
}

/// An unencrypted message, whose contents are plaintext Thrift: a text
/// message whose fields are written by `write`.
private func unencryptedMessage(_ write: (inout ThriftWriter) -> Void) -> String {
  let contents = encoded { writer in
    writer.writeFieldBegin(id: 1, type: .structure)  // contents
    writer.writeFieldBegin(id: 1, type: .structure)  // message
    write(&writer)
    writer.writeFieldStop()  // end the message
    writer.writeFieldStop()  // end the contents union
    writer.writeFieldStop()  // end the holder
  }
  return encodedEvent(
    MessageEvent(
      messageId: "m", senderId: "1111", conversationId: "1111:2222",
      detail: .messageCreate(MessageCreateEvent(contents: contents))))
}

/// Events with a malformed field, each named, with the failure it reports.
private let malformedEvents: [(String, String, XChatError.ThriftFailure)] = [
  (
    "message id's type",
    Base64.encodeStandard(
      encoded {
        $0.writeFieldBegin(id: 2, type: .i32)
        $0.writeI32(1)
        $0.writeFieldStop()
      }),
    .fieldType(field: "message_id", id: 2, actual: .i32, expected: .binary)
  ),
  (
    "message id",
    Base64.encodeStandard(
      encoded {
        $0.writeFieldBegin(id: 2, type: .binary)
        $0.writeBinary([0xFF])
        $0.writeFieldStop()
      }),
    .invalidUTF8
  ),
  (
    "sequence ids",
    deleteEvent {
      $0.writeFieldBegin(id: 1, type: .list)
      $0.writeListBegin(elementType: .i32, count: 0)
    },
    .listElementType(field: "sequence_ids", actual: .i32, expected: .binary)
  ),
  (
    "pinned sequence ids",
    deleteEvent {
      $0.writeFieldBegin(id: 3, type: .map)
      $0.writeMapBegin(keyType: .binary, valueType: .i64, count: 0)
    },
    .mapTypes(field: "pme_sequence_ids", key: .binary, value: .i64)
  ),
]

/// Unencrypted messages with a malformed field in their contents, each
/// named, with the failure it reports.
private let malformedContents: [(String, String, XChatError.ThriftFailure)] = [
  (
    "text",
    unencryptedMessage {
      $0.writeFieldBegin(id: 1, type: .binary)
      $0.writeBinary([0xFF])
    },
    .invalidUTF8
  ),
  (
    "entities",
    unencryptedMessage {
      $0.writeFieldBegin(id: 2, type: .list)
      $0.writeListBegin(elementType: .binary, count: 0)
    },
    .listElementType(field: "entities", actual: .binary, expected: .structure)
  ),
  (
    "additional fields",
    unencryptedMessage {
      $0.writeFieldBegin(id: 10, type: .map)
      $0.writeMapBegin(keyType: .i32, valueType: .binary, count: 0)
    },
    .mapTypes(field: "additional_fields", key: .i32, value: .binary)
  ),
  (
    "attachment",
    unencryptedMessage {
      $0.writeFieldBegin(id: 3, type: .list)
      $0.writeListBegin(elementType: .structure, count: 1)
      $0.writeFieldStop()  // an attachment that sets no variant
    },
    .messageAttachmentWithoutVariant
  ),
  (
    "preview attachment",
    unencryptedMessage {
      $0.writeFieldBegin(id: 4, type: .structure)  // replying_to_preview
      $0.writeFieldBegin(id: 4, type: .list)  // attachments
      $0.writeListBegin(elementType: .structure, count: 1)
      $0.writeFieldStop()  // an attachment that sets no variant
      $0.writeFieldStop()  // end the preview
    },
    .previewAttachmentWithoutVariant
  ),
]
