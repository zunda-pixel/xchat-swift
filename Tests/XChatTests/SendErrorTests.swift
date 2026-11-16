import Testing

@testable import XChat

/// The errors of the sends and `prepareConversationKeyChange`: what they
/// check first (the signing state, then the conversation key, version,
/// sender id and conversation id), the message a reply quotes, a key
/// change's participants, and a send's target, emoji and attachments.
struct SendErrorTests {
  private static let conversationKey = TestVectors.bytes("conversation_key_b64")
  private static let conversationKeyVersion = "1001"
  private static let conversationId = TestVectors.string("event_conversation_id")
  private static let senderId = TestVectors.string("event_sender_id")

  /// A core with random keys, sending as `version`.
  private static func makeCore(version: SendVersion = .v0) throws -> XChatCore {
    let core = XChatCore()
    try core.importKeys(
      identityPrivateKey: generateKeyPair().privateKey,
      signingPrivateKey: generateKeyPair().privateKey,
      publicKeyVersion: "1")
    core.sendVersion = version
    return core
  }

  /// `payload`'s event with a sequence id: a sent event has none until the
  /// server assigns one, and a reply names the message it quotes by it.
  private static func sequenced(_ payload: EncryptedMessagePayload) throws -> String {
    try rewritingEvent(payload.eventB64) { $0.sequenceId = "7" }
  }

  /// A participant of a key change, with the fixture's identity key.
  private static func participant(
    _ userId: String, version: String = "1"
  ) -> ConversationParticipantPublicKey {
    ConversationParticipantPublicKey(
      userId: userId, identityPublicKey: TestVectors.string("identity_public_b64"),
      publicKeyVersion: version)
  }

  // MARK: What sends and key changes check first

  /// A state of a core's keys in which it cannot sign.
  enum SigningState: CaseIterable {
    case noKeys
    case noSigningKey
    case noSigningKeyVersion

    func core() throws -> XChatCore {
      let core = XChatCore()
      switch self {
      case .noKeys:
        break
      case .noSigningKey:
        try core.importKeys(identityPrivateKey: generateKeyPair().privateKey)
      case .noSigningKeyVersion:
        try core.importKeys(
          identityPrivateKey: generateKeyPair().privateKey,
          signingPrivateKey: generateKeyPair().privateKey)
      }
      return core
    }

    var failure: XChatError.StateFailure {
      switch self {
      case .noKeys: .keysNotLoaded
      case .noSigningKey: .signingKeyNotLoaded
      case .noSigningKeyVersion: .signingKeyVersionNotSet
      }
    }
  }

  /// A send or key change given a fault its signing state is checked
  /// before: a 31-byte conversation key, a message to quote that no key
  /// was given for, or a participant whose identity key is not a key.
  enum SigningCall: CaseIterable {
    case message
    case reply
    case reaction
    case reactionRemoval
    case edit
    case keyChange

    /// What the call reports once the core can sign.
    var otherFault: XChatError {
      switch self {
      case .message, .reaction, .reactionRemoval, .edit:
        .invalidInput(.conversationKeyLength(31))
      case .reply:
        .decryption(
          .missingConversationKey(
            .quotedMessage, version: "999", available: [SendErrorTests.conversationKeyVersion]))
      case .keyChange:
        .invalidInput(.participantIdentityKey(userId: "2222"))
      }
    }

    /// Makes the call on `core`; a reply quotes `unopenableB64`.
    func run(on core: XChatCore, quoting unopenableB64: String) throws {
      let shortKey = [UInt8](repeating: 1, count: 31)
      switch self {
      case .message:
        _ = try core.encryptMessage(
          text: "x", conversationId: SendErrorTests.conversationId, conversationKey: shortKey,
          conversationKeyVersion: SendErrorTests.conversationKeyVersion,
          senderId: SendErrorTests.senderId)
      case .reply:
        _ = try core.encryptReply(
          text: "x", replyToEventB64: unopenableB64,
          conversationId: SendErrorTests.conversationId,
          conversationKey: SendErrorTests.conversationKey,
          conversationKeyVersion: SendErrorTests.conversationKeyVersion,
          senderId: SendErrorTests.senderId)
      case .reaction:
        _ = try core.encryptReaction(
          emoji: "👍", targetMessageSequenceId: "5",
          conversationId: SendErrorTests.conversationId, conversationKey: shortKey,
          conversationKeyVersion: SendErrorTests.conversationKeyVersion,
          senderId: SendErrorTests.senderId)
      case .reactionRemoval:
        _ = try core.encryptRemoveReaction(
          emoji: "👍", targetMessageSequenceId: "5",
          conversationId: SendErrorTests.conversationId, conversationKey: shortKey,
          conversationKeyVersion: SendErrorTests.conversationKeyVersion,
          senderId: SendErrorTests.senderId)
      case .edit:
        _ = try core.encryptEdit(
          targetMessageSequenceId: "5", updatedText: "x", targetMessageId: nil,
          conversationId: SendErrorTests.conversationId, conversationKey: shortKey,
          conversationKeyVersion: SendErrorTests.conversationKeyVersion,
          senderId: SendErrorTests.senderId)
      case .keyChange:
        _ = try core.prepareConversationKeyChange(
          participants: [
            SendErrorTests.participant(SendErrorTests.senderId),
            ConversationParticipantPublicKey(
              userId: "2222", identityPublicKey: "not base64!", publicKeyVersion: "1"),
          ],
          senderId: SendErrorTests.senderId, conversationKeyVersion: "5000")
      }
    }
  }

  /// A message under version "999", which no call here is given a key for.
  private static func unopenableQuote() throws -> String {
    try sequenced(
      makeCore().encryptMessage(
        text: "quoted", conversationId: conversationId, conversationKey: conversationKey,
        conversationKeyVersion: "999", senderId: senderId))
  }

  /// Every send and key change checks that a signing key and its version
  /// are loaded before anything it is given, so a core that cannot sign
  /// says so whatever else is wrong. A core with no keys at all says that
  /// no keys are loaded, as the calls that read keys do, and one whose
  /// keys were imported without a signing key says that.
  @Test(arguments: SigningState.allCases, SigningCall.allCases)
  func sendsAndKeyChangesCheckTheSigningStateFirst(
    state: SigningState, call: SigningCall
  ) throws {
    let quoted = try Self.unopenableQuote()
    let core = try state.core()
    #expect(throws: XChatError.invalidState(state.failure)) {
      try call.run(on: core, quoting: quoted)
    }
  }

  /// With the signing key and its version loaded, each call reports the
  /// fault its signing state was checked before.
  @Test(arguments: SigningCall.allCases)
  func aCoreThatCanSignReportsTheOtherFault(call: SigningCall) throws {
    let quoted = try Self.unopenableQuote()
    let core = try Self.makeCore()
    #expect(throws: call.otherFault) {
      try call.run(on: core, quoting: quoted)
    }
  }

  /// A send's conversation key, version, sender id and conversation id.
  struct SendParameters {
    var key = SendErrorTests.conversationKey
    var version = SendErrorTests.conversationKeyVersion
    var senderId = SendErrorTests.senderId
    var conversationId = SendErrorTests.conversationId
  }

  /// A fault in a send's conversation key, version, sender id or
  /// conversation id.
  enum SendParameterFault: CaseIterable {
    case keyOf31Bytes
    case versionWithALeadingZero
    case senderIdOfLetters
    case conversationIdWithAComma
    case emptyConversationId

    var parameters: SendParameters {
      var parameters = SendParameters()
      switch self {
      case .keyOf31Bytes: parameters.key = [UInt8](repeating: 1, count: 31)
      case .versionWithALeadingZero: parameters.version = "01"
      case .senderIdOfLetters: parameters.senderId = "abc"
      case .conversationIdWithAComma: parameters.conversationId = "1111,2222"
      case .emptyConversationId: parameters.conversationId = ""
      }
      return parameters
    }

    var failure: XChatError.InputFailure {
      switch self {
      case .keyOf31Bytes: .conversationKeyLength(31)
      case .versionWithALeadingZero: .conversationKeyVersion("01")
      case .senderIdOfLetters: .senderId("abc")
      case .conversationIdWithAComma: .conversationIdContainsComma("1111,2222")
      case .emptyConversationId: .emptyConversationId
      }
    }
  }

  /// A send given a fault in what it builds, which its parameters are
  /// checked before: an entity out of range, an empty reaction target, or
  /// an empty emoji.
  enum CheckedSend: CaseIterable {
    case message
    case reply
    case reaction
    case reactionRemoval
    case edit

    /// What the send reports once its parameters are right.
    var otherFailure: XChatError.InputFailure {
      switch self {
      case .message, .reply, .edit: .entityRange(start: 0, end: 99)
      case .reaction: .emptyTargetSequenceId
      case .reactionRemoval: .emptyReactionEmoji
      }
    }

    /// Makes the send on `core` with `parameters`; a reply quotes
    /// `quotedB64`.
    func run(
      on core: XChatCore, quoting quotedB64: String, with parameters: SendParameters
    ) throws {
      let entities = [EntityDescriptor(start: 0, end: 99, type: .hashtag)]
      switch self {
      case .message:
        _ = try core.encryptMessage(
          text: "x", conversationId: parameters.conversationId, conversationKey: parameters.key,
          conversationKeyVersion: parameters.version, senderId: parameters.senderId,
          entities: entities)
      case .reply:
        _ = try core.encryptReply(
          text: "x", replyToEventB64: quotedB64, conversationId: parameters.conversationId,
          conversationKey: parameters.key, conversationKeyVersion: parameters.version,
          senderId: parameters.senderId, entities: entities)
      case .reaction:
        _ = try core.encryptReaction(
          emoji: "👍", targetMessageSequenceId: "", conversationId: parameters.conversationId,
          conversationKey: parameters.key, conversationKeyVersion: parameters.version,
          senderId: parameters.senderId)
      case .reactionRemoval:
        _ = try core.encryptRemoveReaction(
          emoji: "", targetMessageSequenceId: "5", conversationId: parameters.conversationId,
          conversationKey: parameters.key, conversationKeyVersion: parameters.version,
          senderId: parameters.senderId)
      case .edit:
        _ = try core.encryptEdit(
          targetMessageSequenceId: "5", updatedText: "x", targetMessageId: nil,
          conversationId: parameters.conversationId, conversationKey: parameters.key,
          conversationKeyVersion: parameters.version, senderId: parameters.senderId,
          entities: entities)
      }
    }
  }

  /// A message `core` sent, which a reply can quote.
  private static func quotableMessage(sentBy core: XChatCore) throws -> String {
    try sequenced(
      core.encryptMessage(
        text: "quoted", conversationId: conversationId, conversationKey: conversationKey,
        conversationKeyVersion: conversationKeyVersion, senderId: senderId))
  }

  /// Every send checks its conversation key, version, sender id and
  /// conversation id before anything else it is given, so each reports a
  /// malformed one alike whatever else is wrong. An empty conversation id
  /// names no conversation, and one with a comma cannot be signed.
  @Test(arguments: CheckedSend.allCases, SendParameterFault.allCases)
  func sendsCheckTheirKeyVersionAndIdsFirst(
    send: CheckedSend, fault: SendParameterFault
  ) throws {
    let core = try Self.makeCore()
    let quoted = try Self.quotableMessage(sentBy: core)
    #expect(throws: XChatError.invalidInput(fault.failure)) {
      try send.run(on: core, quoting: quoted, with: fault.parameters)
    }
  }

  /// With its key, version, sender id and conversation id right, each send
  /// reports the fault in what it builds.
  @Test(arguments: CheckedSend.allCases)
  func aSendWithItsParametersRightReportsTheOtherFault(send: CheckedSend) throws {
    let core = try Self.makeCore()
    let quoted = try Self.quotableMessage(sentBy: core)
    #expect(throws: XChatError.invalidInput(send.otherFailure)) {
      try send.run(on: core, quoting: quoted, with: SendParameters())
    }
  }

  // MARK: Conversation ids

  /// A send given a conversation id that contains a comma.
  enum CommaRefusingSend: CaseIterable {
    case v0Message
    case v1Message
    case reply
  }

  /// A conversation id that contains a comma is refused, not signed: the
  /// signed payload joins its components with commas, so it could be read
  /// as other components. Such an id is no pair of user ids, so it would be
  /// signed as given. It is refused with the other ids and versions, before
  /// what the call builds: from a message of either version, and from a
  /// reply before the quoted message is found in another conversation.
  @Test(arguments: CommaRefusingSend.allCases)
  func aConversationIdWithACommaIsRefused(send: CommaRefusingSend) throws {
    let commaId = "1111,2222"
    let core = try Self.makeCore(version: send == .v1Message ? .v1 : .v0)
    #expect(throws: XChatError.invalidInput(.conversationIdContainsComma(commaId))) {
      switch send {
      case .v0Message, .v1Message:
        _ = try core.encryptMessage(
          text: "x", conversationId: commaId, conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
      case .reply:
        _ = try core.encryptReply(
          text: "a reply", replyToEventB64: TestVectors.string("event_message_b64"),
          conversationId: commaId, conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
      }
    }
  }

  /// A key change refuses a conversation id that contains a comma with its
  /// other ids and versions, before a participant's identity key that is
  /// not base64, which is reported once the comma is gone.
  @Test func aKeyChangeRefusesACommaBeforeItsParticipants() throws {
    let core = try Self.makeCore()
    func prepareKeyChange(conversationId: String) throws {
      _ = try core.prepareConversationKeyChange(
        participants: [
          Self.participant(Self.senderId),
          ConversationParticipantPublicKey(
            userId: "2222", identityPublicKey: "not base64!", publicKeyVersion: "1"),
        ],
        conversationId: conversationId, senderId: Self.senderId, conversationKeyVersion: "5000")
    }
    #expect(throws: XChatError.invalidInput(.conversationIdContainsComma("1111,2222"))) {
      try prepareKeyChange(conversationId: "1111,2222")
    }
    #expect(throws: XChatError.invalidInput(.participantIdentityKey(userId: "2222"))) {
      try prepareKeyChange(conversationId: Self.conversationId)
    }
  }

  /// A key change takes an empty conversation id as none and derives the
  /// one-to-one id from its two participants, as it does without one,
  /// while a send refuses an empty id.
  @Test func aKeyChangeDerivesItsConversationIdForAnEmptyOne() throws {
    let core = try Self.makeCore()
    func prepareKeyChange(conversationId: String?) throws -> PreparedConversationChange {
      try core.prepareConversationKeyChange(
        participants: [Self.participant(Self.senderId), Self.participant("2222")],
        conversationId: conversationId, senderId: Self.senderId, conversationKeyVersion: "5000")
    }
    #expect(try prepareKeyChange(conversationId: "").conversationId == Self.conversationId)
    #expect(try prepareKeyChange(conversationId: nil).conversationId == Self.conversationId)
  }

  // MARK: Replies

  /// A key that does not open the message a reply quotes is reported for
  /// the quoted message, with the version it was given for: the reply's
  /// own conversation key, or a key in `replyToConversationKeys`.
  @Test func replyNamesTheQuotedMessagesKey() throws {
    let core = try Self.makeCore(version: .v1)
    let wrongKey = [UInt8](repeating: 1, count: 32)

    #expect(
      throws: XChatError.decryption(
        .messageContents(
          .quotedMessage, .authenticationFailed,
          key: .conversationKey(version: Self.conversationKeyVersion))),
      "the reply's own key"
    ) {
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_b64"),
        conversationId: Self.conversationId, conversationKey: wrongKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    }

    let quotedVersion = TestVectors.string("message_key_conversation_key_version")
    #expect(
      throws: XChatError.decryption(
        .messageContents(
          .quotedMessage, .authenticationFailed, key: .conversationKey(version: quotedVersion))),
      "a key in replyToConversationKeys"
    ) {
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_key_b64"),
        conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
        replyToConversationKeys: [quotedVersion: wrongKey])
    }
  }

  /// Without a key for the quoted message's version, a reply lists the
  /// versions it has keys for, its own among them, in numeric order.
  @Test func replyListsTheVersionsItHasKeysForInOrder() throws {
    let core = try Self.makeCore(version: .v1)
    let key = [UInt8](repeating: 1, count: 32)
    #expect(
      throws: XChatError.decryption(
        .missingConversationKey(
          .quotedMessage, version: TestVectors.string("message_key_conversation_key_version"),
          available: ["9", "10", Self.conversationKeyVersion]))
    ) {
      try core.encryptReply(
        text: "a reply", replyToEventB64: TestVectors.string("event_message_key_b64"),
        conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
        replyToConversationKeys: ["10": key, "9": key])
    }
  }

  /// An event `encryptReply` cannot quote.
  enum UnquotableEvent: CaseIterable {
    case keyChange
    case messageWithoutContents
    case messageWithoutSequenceId
    case edit
    case reaction

    var failure: XChatError.InputFailure {
      switch self {
      case .keyChange: .notMessageEvent(.quotedMessage)
      case .messageWithoutContents: .noContents(.quotedMessage)
      case .messageWithoutSequenceId: .quotedMessageWithoutSequenceId
      case .edit: .messageIsEdit(.quotedMessage)
      case .reaction: .notTextMessage(.quotedMessage)
      }
    }
  }

  /// An event that cannot be quoted is reported by what it is, each a case
  /// of its own for the quoted message: a key change, a message event
  /// without contents or a sequence id, an edit, and a reaction.
  @Test(arguments: UnquotableEvent.allCases)
  func replyNamesWhyTheEventCannotBeQuoted(event kind: UnquotableEvent) throws {
    let core = try Self.makeCore()
    let eventB64: String
    switch kind {
    case .keyChange:
      eventB64 = TestVectors.string("event_key_change_b64")
    case .messageWithoutContents:
      eventB64 = try replacingContents(TestVectors.string("event_message_b64"), with: nil)
    case .messageWithoutSequenceId:
      eventB64 =
        try core.encryptMessage(
          text: "quoted", conversationId: Self.conversationId,
          conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId
        ).eventB64
    case .edit:
      eventB64 = try Self.sequenced(
        core.encryptEdit(
          targetMessageSequenceId: "5", updatedText: "edited", targetMessageId: "m",
          conversationId: Self.conversationId, conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId))
    case .reaction:
      eventB64 = try Self.sequenced(
        core.encryptReaction(
          emoji: "👍", targetMessageSequenceId: "5", conversationId: Self.conversationId,
          conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId))
    }
    #expect(throws: XChatError.invalidInput(kind.failure)) {
      try core.encryptReply(
        text: "a reply", replyToEventB64: eventB64, conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    }
  }

  /// A fault in a reply's own parameters, checked before the message it
  /// quotes is opened.
  enum ReplyParameterFault: CaseIterable {
    /// A 31-byte key, quoting a message under the conversation key itself
    /// (v0).
    case keyOf31BytesQuotingV0
    /// A 31-byte key, quoting a message under a key derived from it (v1).
    case keyOf31BytesQuotingV1
    case versionWithALeadingZero
    case senderIdOfLetters
    case senderIdWithALeadingZero
  }

  /// A reply's own conversation key, version and sender id are reported as
  /// invalid parameters, not as the quoted message failing to open or to
  /// match the reply's conversation, whether the quoted message is under
  /// the conversation key itself (v0) or a key derived from it (v1).
  @Test(arguments: ReplyParameterFault.allCases)
  func replyChecksItsOwnParametersBeforeTheQuotedMessage(fault: ReplyParameterFault) throws {
    let core = try Self.makeCore(version: .v1)
    var quotedB64 = TestVectors.string("event_message_b64")
    var parameters = SendParameters()
    let failure: XChatError.InputFailure
    switch fault {
    case .keyOf31BytesQuotingV0:
      parameters.key = [UInt8](repeating: 0, count: 31)
      failure = .conversationKeyLength(31)
    case .keyOf31BytesQuotingV1:
      quotedB64 = TestVectors.string("event_message_key_b64")
      parameters.version = TestVectors.string("message_key_conversation_key_version")
      parameters.key = [UInt8](repeating: 0, count: 31)
      failure = .conversationKeyLength(31)
    case .versionWithALeadingZero:
      parameters.version = "0" + Self.conversationKeyVersion
      failure = .conversationKeyVersion(parameters.version)
    case .senderIdOfLetters:
      // Opened first, the quoted message would not decrypt under this key.
      parameters.key = [UInt8](repeating: 1, count: 32)
      parameters.senderId = "abc"
      failure = .senderId(parameters.senderId)
    case .senderIdWithALeadingZero:
      // A one-to-one id given as the other user's alone would join this
      // sender id into a conversation the quoted message is not in.
      parameters.conversationId = "2222"
      parameters.senderId = "0" + Self.senderId
      failure = .senderId(parameters.senderId)
    }
    #expect(throws: XChatError.invalidInput(failure)) {
      try core.encryptReply(
        text: "a reply", replyToEventB64: quotedB64, conversationId: parameters.conversationId,
        conversationKey: parameters.key, conversationKeyVersion: parameters.version,
        senderId: parameters.senderId)
    }
  }

  // MARK: Key changes

  /// An identity key the conversation key cannot be encrypted to.
  enum BadIdentityKey: CaseIterable {
    case notBase64
    case notAPoint
    case spkiOfAnotherCurve

    func base64() throws -> String {
      switch self {
      case .notBase64:
        return "not base64!"
      case .notAPoint:
        return Base64.encodeStandard([0x04] + [UInt8](repeating: 0, count: 64))
      case .spkiOfAnotherCurve:
        var otherCurve = try spkiDER(publicKey: generateKeyPair().publicKey)
        // The last arc of the named-curve OID.
        otherCurve[22] = 0x02
        return Base64.encodeStandard(otherCurve)
      }
    }
  }

  /// An identity key the conversation key cannot be encrypted to names the
  /// participant it belongs to, whether it is not base64, not a P-256
  /// point, or an SPKI naming another curve.
  @Test(arguments: BadIdentityKey.allCases)
  func keyChangeNamesTheParticipantWithABadKey(identityKey: BadIdentityKey) throws {
    let core = try Self.makeCore()
    let badKey = try identityKey.base64()
    #expect(throws: XChatError.invalidInput(.participantIdentityKey(userId: "2222"))) {
      try core.prepareConversationKeyChange(
        participants: [
          Self.participant(Self.senderId),
          ConversationParticipantPublicKey(
            userId: "2222", identityPublicKey: badKey, publicKeyVersion: "1"),
        ],
        senderId: Self.senderId, conversationKeyVersion: "5000")
    }
  }

  /// What is wrong with a key change's participants.
  enum ParticipantsFault: CaseIterable {
    case noParticipants
    case userIdZero
    case userIdWithALeadingZero
    case keyVersionWithALeadingZero
    case oneUser
    case threeUsers

    var participants: [ConversationParticipantPublicKey] {
      let me = SendErrorTests.participant(SendErrorTests.senderId)
      return switch self {
      case .noParticipants: []
      case .userIdZero: [me, SendErrorTests.participant("0")]
      case .userIdWithALeadingZero: [me, SendErrorTests.participant("01")]
      case .keyVersionWithALeadingZero: [me, SendErrorTests.participant("2222", version: "01")]
      case .oneUser: [me, me]
      case .threeUsers:
        [me, SendErrorTests.participant("2222"), SendErrorTests.participant("3333")]
      }
    }

    var failure: XChatError.InputFailure {
      switch self {
      case .noParticipants: .noParticipants
      case .userIdZero: .participantUserId("0")
      case .userIdWithALeadingZero: .participantUserId("01")
      case .keyVersionWithALeadingZero: .participantKeyVersion("01")
      case .oneUser: .conversationIdNotDerivable(distinctUsers: 1)
      case .threeUsers: .conversationIdNotDerivable(distinctUsers: 3)
      }
    }
  }

  /// A key change's participants are checked before any key is made: an
  /// empty list, a user id or key version not in canonical decimal form,
  /// and, without a conversation id, participants that are not two users,
  /// from whom no one-to-one id derives.
  @Test(arguments: ParticipantsFault.allCases)
  func keyChangeValidatesItsParticipants(fault: ParticipantsFault) throws {
    let core = try Self.makeCore()
    #expect(throws: XChatError.invalidInput(fault.failure)) {
      try core.prepareConversationKeyChange(
        participants: fault.participants, senderId: Self.senderId,
        conversationKeyVersion: "5000")
    }
  }

  // MARK: Targets, emoji and attachments

  /// A reaction, a reaction's removal or an edit with an empty target
  /// sequence id or emoji.
  enum TargetFault: CaseIterable {
    case reactionWithoutTarget
    case reactionWithoutEmoji
    case removalWithoutTarget
    case removalWithoutEmoji
    case editWithoutTarget
  }

  /// Reactions and edits name the message they target by its sequence id,
  /// and a reaction needs an emoji: either one empty is refused.
  @Test(arguments: TargetFault.allCases)
  func reactionAndEditTargetsAreChecked(fault: TargetFault) throws {
    let core = try Self.makeCore()
    func add(emoji: String, target: String) throws {
      _ = try core.encryptReaction(
        emoji: emoji, targetMessageSequenceId: target, conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    }
    func remove(emoji: String, target: String) throws {
      _ = try core.encryptRemoveReaction(
        emoji: emoji, targetMessageSequenceId: target, conversationId: Self.conversationId,
        conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
    }
    switch fault {
    case .reactionWithoutTarget:
      #expect(throws: XChatError.invalidInput(.emptyTargetSequenceId)) {
        try add(emoji: "👍", target: "")
      }
    case .reactionWithoutEmoji:
      #expect(throws: XChatError.invalidInput(.emptyReactionEmoji)) {
        try add(emoji: "", target: "5")
      }
    case .removalWithoutTarget:
      #expect(throws: XChatError.invalidInput(.emptyTargetSequenceId)) {
        try remove(emoji: "👍", target: "")
      }
    case .removalWithoutEmoji:
      #expect(throws: XChatError.invalidInput(.emptyReactionEmoji)) {
        try remove(emoji: "", target: "5")
      }
    case .editWithoutTarget:
      #expect(throws: XChatError.invalidInput(.emptyTargetSequenceId)) {
        try core.encryptEdit(
          targetMessageSequenceId: "", updatedText: "edited", targetMessageId: "m",
          conversationId: Self.conversationId, conversationKey: Self.conversationKey,
          conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId)
      }
    }
  }

  /// Each invalid field of an attachment descriptor is its own case, with
  /// the index of the descriptor it is in, and for a URL card's image,
  /// which image it is. Descriptors are checked in order, and each one's
  /// fields in the order they are declared, so the first invalid field is
  /// reported. Valid descriptors of every kind come before the broken one,
  /// so its index is not always 0, and an invalid one follows it.
  @Test(arguments: attachmentFaults, 0...validAttachments.count)
  func eachInvalidAttachmentFieldNamesItsCaseAndIndex(
    fault: AttachmentFault, index: Int
  ) throws {
    let core = try Self.makeCore()
    let attachments =
      Array(validAttachments.prefix(index)) + [fault.descriptor, mediaDescriptor(mediaHashKey: "")]
    #expect(throws: XChatError.invalidInput(.attachment(index: index, fault.failure))) {
      try core.encryptMessage(
        text: "x", conversationId: Self.conversationId, conversationKey: Self.conversationKey,
        conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
        attachments: attachments)
    }
  }

  /// The valid descriptors the faults above come after are valid, so the
  /// faults are the ones reported.
  @Test func theValidAttachmentsAreValid() throws {
    _ = try Self.makeCore().encryptMessage(
      text: "x", conversationId: Self.conversationId, conversationKey: Self.conversationKey,
      conversationKeyVersion: Self.conversationKeyVersion, senderId: Self.senderId,
      attachments: validAttachments)
  }
}

/// An invalid attachment descriptor, with the failure it is reported as.
struct AttachmentFault: Sendable, CustomTestStringConvertible {
  var failure: XChatError.AttachmentFailure
  var descriptor: AttachmentDescriptor

  var testDescription: String { "\(failure)" }
}

/// A media attachment, valid unless a field is given.
private func mediaDescriptor(
  mediaHashKey: String = "h", width: Int64 = 1, height: Int64 = 1,
  filesizeBytes: Int64 = 1, filename: String = "f", mediaType: Int32? = 1,
  plaintextSHA256: String? = nil
) -> AttachmentDescriptor {
  .media(
    mediaHashKey: mediaHashKey, width: width, height: height,
    filesizeBytes: filesizeBytes, filename: filename, mediaType: mediaType,
    durationMilliseconds: nil, plaintextSHA256: plaintextSHA256)
}

/// A URL card's image, valid unless a field is given.
private func cardImage(
  mediaHashKey: String = "i", filesizeBytes: Int64 = 1, filename: String = "i.png",
  width: Int64? = 1, height: Int64? = 1
) -> UrlAttachmentImageDescriptor {
  UrlAttachmentImageDescriptor(
    mediaHashKey: mediaHashKey, filesizeBytes: filesizeBytes, filename: filename,
    width: width, height: height)
}

/// A URL card, valid unless a field is given.
private func cardDescriptor(
  url: String = "https://example.com", banner: UrlAttachmentImageDescriptor? = cardImage(),
  favicon: UrlAttachmentImageDescriptor? = cardImage()
) -> AttachmentDescriptor {
  .url(url: url, displayTitle: nil, bannerImage: banner, faviconImage: favicon)
}

/// Valid descriptors of every kind.
private let validAttachments = [
  mediaDescriptor(), cardDescriptor(), .post(restId: "1", postURL: nil),
]

/// Every invalid field of a media attachment, a URL card and a post, each
/// of a card image's faults for the banner and the favicon, and
/// descriptors with more than one invalid field, whose first is reported.
private let attachmentFaults: [AttachmentFault] = {
  let notSHA256 = Base64.encodeStandard([UInt8](repeating: 0, count: 31))
  var faults: [(XChatError.AttachmentFailure, AttachmentDescriptor)] = [
    (.emptyMediaHashKey, mediaDescriptor(mediaHashKey: "")),
    (.negativeWidth, mediaDescriptor(width: -1)),
    (.negativeHeight, mediaDescriptor(height: -1)),
    (.nonPositiveFilesize, mediaDescriptor(filesizeBytes: 0)),
    (.emptyFilename, mediaDescriptor(filename: "")),
    (.unknownMediaType(7), mediaDescriptor(mediaType: 7)),
    (.plaintextSHA256, mediaDescriptor(plaintextSHA256: "not base64!")),
    (.plaintextSHA256, mediaDescriptor(plaintextSHA256: notSHA256)),
    (.emptyURL, cardDescriptor(url: "")),
    (.postWithoutReference, .post(restId: nil, postURL: nil)),
    (.postWithoutReference, .post(restId: "", postURL: "")),
    // The first invalid field is reported.
    (.negativeWidth, mediaDescriptor(width: -1, height: -1)),
    (.emptyMediaHashKey, mediaDescriptor(mediaHashKey: "", filesizeBytes: 0)),
    (
      .cardImage(.banner, .emptyFilename),
      cardDescriptor(banner: cardImage(filename: ""), favicon: nil)
    ),
    (
      .cardImage(.banner, .nonPositiveFilesize),
      cardDescriptor(banner: cardImage(filesizeBytes: 0), favicon: cardImage(mediaHashKey: ""))
    ),
    (
      .cardImage(.favicon, .negativeHeight),
      cardDescriptor(banner: nil, favicon: cardImage(height: -1))
    ),
    (.emptyURL, cardDescriptor(url: "", banner: cardImage(mediaHashKey: ""))),
  ]
  let imageFaults: [(XChatError.CardImageFailure, UrlAttachmentImageDescriptor)] = [
    (.emptyMediaHashKey, cardImage(mediaHashKey: "")),
    (.nonPositiveFilesize, cardImage(filesizeBytes: 0)),
    (.emptyFilename, cardImage(filename: "")),
    (.negativeWidth, cardImage(width: -1)),
    (.negativeHeight, cardImage(height: -1)),
  ]
  for (failure, broken) in imageFaults {
    faults.append((.cardImage(.banner, failure), cardDescriptor(banner: broken)))
    faults.append((.cardImage(.favicon, failure), cardDescriptor(favicon: broken)))
  }
  return faults.map { AttachmentFault(failure: $0, descriptor: $1) }
}()
