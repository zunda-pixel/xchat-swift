import Foundation
import Testing
import XChat

/// An error the SDK throws describes its case and values through
/// `Error.localizedDescription`, even when the caller holds it as
/// `any Error`, and the description matches `CustomStringConvertible`'s.
@Test func localizedDescriptionDescribesTheCase() throws {
  let error = #expect(throws: XChatError.invalidState(.keysNotLoaded)) {
    try XChatCore().exportKeys()
  }
  let anyError: any Error = try #require(error)
  #expect(anyError.localizedDescription == "Keys are not loaded: import keys first")
  #expect(anyError.localizedDescription == String(describing: anyError))

  let withValue: any Error = XChatError.invalidInput(.conversationKeyLength(31))
  #expect(withValue.localizedDescription == "Conversation key must be 32 bytes, got 31")
}

/// The debug description is the expression that builds the error, not the
/// English sentence: every nested case is written as the pattern to match,
/// with its values and their labels, and without module-qualified type
/// names.
@Test(arguments: [
  (
    XChatError.invalidInput(.conversationKeyLength(31)),
    "XChatError.invalidInput(.conversationKeyLength(31))"
  ),
  (.invalidState(.keysNotLoaded), "XChatError.invalidState(.keysNotLoaded)"),
  (
    .decryption(
      .messageContents(.quotedMessage, .authenticationFailed, key: .carriedByReply(version: "2"))
    ),
    #"XChatError.decryption(.messageContents(.quotedMessage, .authenticationFailed, "#
      + #"key: .carriedByReply(version: "2")))"#
  ),
  (
    .invalidInput(.attachment(index: 0, .nonPositiveFilesize)),
    "XChatError.invalidInput(.attachment(index: 0, .nonPositiveFilesize))"
  ),
  (
    .invalidInput(.attachment(index: 1, .cardImage(.favicon, .negativeHeight))),
    "XChatError.invalidInput(.attachment(index: 1, .cardImage(.favicon, .negativeHeight)))"
  ),
  (
    .invalidInput(.mediaHashKeyNotFound("h", available: ["a", "b"])),
    #"XChatError.invalidInput(.mediaHashKeyNotFound("h", available: ["a", "b"]))"#
  ),
  (
    .invalidInput(.mediaHashKeyNotFound("h", available: [])),
    #"XChatError.invalidInput(.mediaHashKeyNotFound("h", available: []))"#
  ),
  (
    .decryption(.file(.unknownTag(16), mediaHashKey: nil)),
    "XChatError.decryption(.file(.unknownTag(16), mediaHashKey: nil))"
  ),
  (
    .decryption(.file(.truncated, mediaHashKey: "h")),
    #"XChatError.decryption(.file(.truncated, mediaHashKey: "h"))"#
  ),
  (
    .parse(.event(.thrift(.fieldType(field: "id", id: 1, actual: .binary, expected: .i64)))),
    #"XChatError.parse(.event(.thrift(.fieldType(field: "id", id: 1, actual: .binary, "#
      + #"expected: .i64))))"#
  ),
  (
    .verification(.rejected(.keyChange, .signatureVersionTooOld(2, minimum: 7))),
    "XChatError.verification(.rejected(.keyChange, .signatureVersionTooOld(2, minimum: 7)))"
  ),
  (
    .verification(.rejected(.message, .invalidSigningPublicKey(senderId: "5", keyVersion: "1"))),
    #"XChatError.verification(.rejected(.message, .invalidSigningPublicKey(senderId: "5", "#
      + #"keyVersion: "1")))"#
  ),
  (
    .invalidInput(.conversationIdContainsComma("1,2")),
    #"XChatError.invalidInput(.conversationIdContainsComma("1,2"))"#
  ),
  (
    .internalError(.unexpected(#"say "hi""#)),
    #"XChatError.internalError(.unexpected("say \"hi\""))"#
  ),
])
func debugDescriptionIsTheExpressionThatBuildsTheError(error: XChatError, expected: String) {
  #expect(String(reflecting: error) == expected)
}

/// The nested enums print as their cases, not as sentence fragments.
@Test func nestedValuesPrintAsTheirCases() {
  #expect(String(describing: XChatError.MessageRole.quotedMessage) == "quotedMessage")
  #expect(String(describing: XChatError.SignedEvent.keyChange) == "keyChange")
}

/// The sending calls share cases with the receiving ones, so those cases
/// describe what is wrong without telling the caller to pass a received
/// event or key changes to decryptEvents. A quoted event that is not a
/// message is described without telling the caller to pass a message's
/// event: from a received reply, the caller passed the reply, and the
/// sender embedded the quoted event.
@Test func sharedCasesDescribeTheFaultForEitherDirection() {
  #expect(
    XChatError.invalidInput(.notMessageEvent(.quotedMessage)).description
      == "The quoted event is not a message event")
  let notFound = XChatError.invalidInput(.mediaHashKeyNotFound("h", available: ["a", "b"]))
  #expect(
    notFound.description
      == "The media_hash_key 'h' is not among the media hash keys this call can use: a, b")
  let noMedia = XChatError.invalidInput(.mediaHashKeyNotFound("h", available: []))
  #expect(
    noMedia.description
      == "The media_hash_key 'h' is not among the media hash keys this call can use: there "
      + "are none")
}

/// An empty conversation id is described as the other empty values a
/// send refuses are.
@Test func emptyConversationIdIsDescribedAsEmpty() {
  #expect(
    XChatError.invalidInput(.emptyConversationId).description
      == "Invalid conversation_id: must not be empty")
}

/// A missing conversation key lists the versions there were keys for,
/// which in decryptEvents include those adopted from the batch's key
/// changes, so the description does not say they were given. One version
/// is named in the singular.
@Test func missingKeysListTheVersionsThereWereKeysFor() {
  let missingKey = XChatError.decryption(
    .missingConversationKey(.quotedMessage, version: "2", available: ["1", "3"]))
  #expect(
    missingKey.description
      == "The quoted message is encrypted under conversation-key version '2', and there was "
      + "no key for it; there were keys for versions 1, 3")
  let oneKey = XChatError.decryption(
    .missingConversationKey(.quotedMessage, version: "2", available: ["1"]))
  #expect(
    oneKey.description
      == "The quoted message is encrypted under conversation-key version '2', and there was "
      + "no key for it; there was a key for version 1")
  let noKeys = XChatError.decryption(
    .missingConversationKey(.message, version: "2", available: []))
  #expect(
    noKeys.description
      == "The message is encrypted under conversation-key version '2', and there were no "
      + "conversation keys")
}

/// An unverifiable event is described with every reason its signature goes
/// unchecked, including a given key whose identity binding does not
/// verify; only a message is unverifiable for being unencrypted.
@Test func unverifiableNamesWhyTheSignatureWentUnchecked() {
  #expect(
    XChatError.verification(.unverifiable(.message)).description
      == "Message signature could not be verified: the message is not encrypted (an "
      + "unencrypted message is never verified), the event carries no signature, no signing "
      + "key of its sender was given at its key version (a key given with an identity-key "
      + "binding that does not verify is not used), or the signed payload cannot be rebuilt "
      + "from the event")
  #expect(
    XChatError.verification(.unverifiable(.keyChange)).description
      == "KeyChange signature could not be verified: the event carries no signature, no "
      + "signing key of its sender was given at its key version (a key given with an "
      + "identity-key binding that does not verify is not used), or the signed payload "
      + "cannot be rebuilt from the event")
}

/// A message's contents that do not decrypt are described with the message
/// and the key they were opened with.
@Test func contentsFailuresNameTheMessageAndKey() {
  let wrongKey = XChatError.decryption(
    .messageContents(.quotedMessage, .authenticationFailed, key: .carriedByReply(version: "2")))
  #expect(
    wrongKey.description
      == "The contents of the quoted message do not decrypt under the key the reply carries "
      + "for it (no conversation key was given for version '2'): it is not the key they were "
      + "encrypted under, or they are corrupted")
  let shortKey = XChatError.decryption(
    .messageContents(.message, .keyLength(31), key: .conversationKey(version: "1")))
  #expect(
    shortKey.description
      == "The contents of the message cannot be decrypted under the conversation key for "
      + "version '1': it is 31 bytes, not 32")
}

/// Every description is a sentence that starts with a capital letter,
/// whatever its case and role, including base64 and hex that fail alone
/// or in an event.
@Test(arguments: [
  XChatError.invalidInput(.participantIdentityKey(userId: "5")),
  .invalidInput(.noParticipants),
  .invalidInput(.conversationIdNotDerivable(distinctUsers: 3)),
  .invalidInput(.notMessageEvent(.message)),
  .invalidInput(.notMessageEvent(.quotedMessage)),
  .invalidInput(.messageIsEdit(.message)),
  .invalidInput(.notTextMessage(.quotedMessage)),
  .invalidInput(.notEncrypted(.message)),
  .invalidInput(.noContents(.quotedMessage)),
  .invalidInput(.quotedMessageWithoutSequenceId),
  .invalidInput(.conversationIdContainsComma("1,2")),
  .invalidInput(.emptyConversationId),
  .invalidInput(.quotedMessageNotEmbedded),
  .invalidInput(.quotedMessageInOtherConversation),
  .invalidInput(.emptyMediaHashKey),
  .invalidInput(.mediaHashKeyNotFound("h", available: [])),
  .invalidInput(.quotedMediaHashKey("h")),
  .invalidInput(.attachment(index: 0, .emptyURL)),
  .invalidState(.keysNotLoaded),
  .invalidState(.signingKeyNotLoaded),
  .invalidState(.signingKeyVersionNotSet),
  .parse(.base64(.invalidLength(1))),
  .parse(.hex(.invalidByte(0x0A))),
  .parse(.event(.base64(.invalidByte(UInt8(ascii: "!"))))),
  .parse(.event(.thrift(.unexpectedEnd))),
  .parse(.messageContents(.quotedMessage, .invalidUTF8)),
  .decryption(.messageContents(.message, .ciphertextTooShort, key: .conversationKey(version: "1"))),
  .decryption(.file(.authenticationFailed, mediaHashKey: nil)),
  .decryption(.file(.unknownTag(4), mediaHashKey: "h")),
  .decryption(.missingConversationKey(.message, version: "1", available: [])),
  .decryption(.missingSenderOrMessageId(.quotedMessage)),
  .decryption(.nonNumericSenderId(.message, "x")),
  .verification(.rejected(.keyChange, .malformedSignature)),
  .internalError(.sodiumInitializationFailed),
  .internalError(.unexpected("Other()")),
])
func descriptionsStartWithACapitalLetter(error: XChatError) throws {
  let first = try #require(error.description.first)
  #expect(first.isUppercase, "\(error.description)")
}

/// Nested failures and their whole descriptions, for
/// `nestedFailuresAreFragmentsAfterAColon`. Typed apart from the test, so
/// the compiler need not infer the type of the literal.
private let nestedFailureDescriptions: [(XChatError, String)] = [
  (.parse(.base64(.dataAfterPadding)), "Invalid base64: '=' is followed by data"),
  (.parse(.event(.base64(.dataAfterPadding))), "Invalid base64 event: '=' is followed by data"),
  (
    .parse(.base64(.invalidByte(UInt8(ascii: "!")))),
    "Invalid base64: byte '!' (0x21) is not in the alphabet"
  ),
  (
    .parse(.event(.base64(.invalidByte(UInt8(ascii: "!"))))),
    "Invalid base64 event: byte '!' (0x21) is not in the alphabet"
  ),
  (
    .parse(.base64(.invalidLength(5))),
    "Invalid base64: 5 characters before any '=', a length no bytes encode to"
  ),
  (
    .parse(.event(.base64(.invalidLength(1)))),
    "Invalid base64 event: 1 character before any '=', a length no bytes encode to"
  ),
  (
    .parse(.base64(.excessPadding(4))),
    "Invalid base64: 4 '=' of padding, where at most 2 are accepted"
  ),
  (
    .parse(.event(.base64(.excessPadding(3)))),
    "Invalid base64 event: 3 '=' of padding, where at most 2 are accepted"
  ),
  (.parse(.hex(.oddLength(1))), "Invalid hex: 1 byte, an odd number"),
  (.parse(.hex(.oddLength(3))), "Invalid hex: 3 bytes, an odd number"),
  (.parse(.hex(.invalidByte(0x0A))), "Invalid hex: byte 0x0A is not a hex digit"),
  (
    .parse(
      .event(.thrift(.fieldType(field: "message_id", id: 2, actual: .i32, expected: .binary)))),
    "Thrift parse error: field message_id (#2) is i32, expected binary"
  ),
  (
    .parse(.messageContents(.quotedMessage, .invalidUTF8)),
    "Content parse error in the quoted message: input has invalid UTF-8"
  ),
  (
    .invalidInput(.attachment(index: 2, .plaintextSHA256)),
    "Invalid attachments[2]: plaintext_sha256 must be the base64 SHA-256 of the file's "
      + "plaintext bytes"
  ),
  (
    .verification(.rejected(.message, .malformedSignature)),
    "Message signature verification failed: the signature is not a 64-byte ECDSA P-256 "
      + "signature"
  ),
  (
    .verification(.rejected(.message, .mismatch(senderId: "5", keyVersion: "1"))),
    "Message signature verification failed: the signature does not match the event under "
      + "the signing key of sender '5' for key version '1'"
  ),
  (
    .verification(.rejected(.keyChange, .invalidSigningPublicKey(senderId: "5", keyVersion: "2"))),
    "KeyChange signature verification failed: the signing key of sender '5' for key version "
      + "'2' is not a P-256 public key"
  ),
]

/// What a nested failure adds follows the colon of the case that holds it
/// as a fragment, starting as it would mid-sentence: the case says what
/// was read, and the fragment does not repeat it. Base64 is described the
/// same alone and in an event, and a count of one takes the singular.
@Test(arguments: nestedFailureDescriptions)
func nestedFailuresAreFragmentsAfterAColon(error: XChatError, expected: String) throws {
  #expect(error.description == expected)
  let colon = try #require(error.description.range(of: ": "))
  let fragment = error.description[colon.upperBound...]
  #expect(fragment.first?.isUppercase == false, "\(error.description)")
}

/// A count of one takes the singular, and any other count the plural.
@Test func countsOfOneAreSingular() {
  #expect(
    XChatError.invalidInput(.conversationIdNotDerivable(distinctUsers: 1)).description
      == "Cannot derive a one-to-one conversation id from 1 distinct user; pass "
      + "conversation_id explicitly for group conversations")
  #expect(
    XChatError.invalidInput(.conversationIdNotDerivable(distinctUsers: 3)).description
      == "Cannot derive a one-to-one conversation id from 3 distinct users; pass "
      + "conversation_id explicitly for group conversations")
  #expect(
    XChatError.decryption(
      .messageContents(.message, .keyLength(1), key: .conversationKey(version: "1"))
    ).description
      == "The contents of the message cannot be decrypted under the conversation key for "
      + "version '1': it is 1 byte, not 32")
}

/// A URL card's image is named by its field, before the image's own field.
@Test func cardImageFailuresNameTheImage() {
  #expect(
    XChatError.invalidInput(.attachment(index: 1, .cardImage(.banner, .emptyFilename)))
      .description == "Invalid attachments[1]: banner_image.filename must not be empty")
  #expect(
    XChatError.invalidInput(.attachment(index: 0, .cardImage(.favicon, .negativeWidth)))
      .description == "Invalid attachments[0]: favicon_image.width must not be negative")
}

/// Each case reports the kind the other chat-xdk bindings name it by.
@Test(arguments: [
  (XChatError.invalidInput(.noParticipants), "invalid_input"),
  (.invalidState(.signingKeyNotLoaded), "invalid_state"),
  (.parse(.base64(.dataAfterPadding)), "parse"),
  (.decryption(.file(.truncated, mediaHashKey: nil)), "decryption"),
  (.verification(.unverifiable(.message)), "verification"),
  (.internalError(.sodiumInitializationFailed), "internal"),
])
func kindsUseTheBindingsNames(error: XChatError, kind: String) {
  #expect(error.kind.rawValue == kind)
}

/// A byte that is not a hex digit is reported alone: the rest of the input
/// may be a key, so the error does not keep it.
@Test func hexFailureKeepsOnlyTheInvalidByte() {
  #expect(throws: XChatError.parse(.hex(.invalidByte(UInt8(ascii: "g"))))) {
    try Hex.decode("00ff0g")
  }
}

/// A byte that is not in the alphabet is described as hex, after its
/// character only when that is printable ASCII: a byte from 0x80 up is
/// part of a multi-byte character, and a control character would be
/// written into the text.
@Test func invalidBytesAreDescribedAsHex() {
  #expect(
    XChatError.parse(.base64(.invalidByte(UInt8(ascii: "!")))).description
      == "Invalid base64: byte '!' (0x21) is not in the alphabet")
  #expect(
    XChatError.parse(.base64(.invalidByte(0xC3))).description
      == "Invalid base64: byte 0xC3 is not in the alphabet")
  #expect(
    XChatError.parse(.hex(.invalidByte(0x0A))).description
      == "Invalid hex: byte 0x0A is not a hex digit")
}

/// A Thrift type byte that names no type is described as hex alone, even
/// when it is a printable character: it is not part of a string.
@Test func unknownThriftTypesAreDescribedAsHex() {
  #expect(
    XChatError.parse(.event(.thrift(.unknownType(0x05)))).description
      == "Thrift parse error: unknown type byte 0x05")
  #expect(
    XChatError.parse(.messageContents(.message, .unknownType(0x41))).description
      == "Content parse error in the message: unknown type byte 0x41")
}

/// Hex of an odd length reports that length.
@Test func hexOfAnOddLengthReportsIt() {
  #expect(throws: XChatError.parse(.hex(.oddLength(3)))) {
    try Hex.decode("abc")
  }
}

/// Base64 whose characters before any `=` number one more than a multiple
/// of four reports that number, padding or not, from either decoder and
/// from an event that travels as base64.
@Test func base64OfAnImpossibleLengthReportsIt() {
  #expect(throws: XChatError.parse(.base64(.invalidLength(5)))) {
    try Base64.decodeStandard("AAAAA")
  }
  #expect(throws: XChatError.parse(.base64(.invalidLength(5)))) {
    try Base64.decodeURLSafe("AAAAA=")
  }
  #expect(throws: XChatError.parse(.event(.base64(.invalidLength(1))))) {
    try XChatCore().decryptEvent("A")
  }
}

/// Base64 with data after its `=` padding is refused from either decoder
/// and from an event that travels as base64.
@Test func base64WithDataAfterPaddingIsRefused() {
  #expect(throws: XChatError.parse(.base64(.dataAfterPadding))) {
    try Base64.decodeStandard("AA=A")
  }
  #expect(throws: XChatError.parse(.base64(.dataAfterPadding))) {
    try Base64.decodeURLSafe("AA=A")
  }
  #expect(throws: XChatError.parse(.event(.base64(.dataAfterPadding)))) {
    try XChatCore().decryptEvent("AA=A")
  }
}

/// Base64 that ends in more than two `=` reports how many, whatever its
/// length; a length that is also invalid is reported first.
@Test func base64WithExcessPaddingReportsIt() throws {
  #expect(throws: XChatError.parse(.base64(.excessPadding(3)))) {
    try Base64.decodeURLSafe("AA===")
  }
  #expect(throws: XChatError.parse(.base64(.excessPadding(4)))) {
    try Base64.decodeStandard("AAAA====")
  }
  #expect(throws: XChatError.parse(.base64(.invalidLength(1)))) {
    try Base64.decodeStandard("A===")
  }
  // Up to two are accepted whatever the length.
  #expect(try Base64.decodeStandard("AAAA==") == [0, 0, 0])
}

/// Errors are Hashable, so a caller can collect the distinct failures of a
/// batch.
@Test func errorsAreHashable() {
  let errors: Set<XChatError> = [
    .invalidState(.keysNotLoaded),
    .invalidState(.keysNotLoaded),
    .parse(.event(.thrift(.fieldType(field: "id", id: 1, actual: .binary, expected: .i64)))),
  ]
  #expect(errors.count == 2)
}

/// A core that can send and prepare key changes, with the fixture's keys.
private func sendingCore() throws -> XChatCore {
  let core = XChatCore()
  try core.importKeys(
    identityPrivateKey: TestVectors.bytes("identity_private_b64"),
    signingPrivateKey: TestVectors.bytes("signing_private_b64"),
    publicKeyVersion: "1")
  return core
}

/// Each of these is digits, or a sign and digits, and is still refused as
/// a user id: zero is not positive, a leading zero or a sign is not
/// canonical, and a value past `Int64.max` does not fit. The description
/// states the whole rule, so it says which part the value breaks.
@Test(arguments: ["0", "007", "+1", "9223372036854775808"])
func userIdsAreDescribedByTheWholeRule(value: String) throws {
  let rule =
    "pass the user id as a positive integer that fits in an Int64, in decimal digits with no "
    + "sign or leading zero"
  let core = try sendingCore()
  let sender = #expect(throws: XChatError.invalidInput(.senderId(value))) {
    try core.encryptMessage(
      text: "x", conversationId: "1111:2222", conversationKey: [UInt8](repeating: 1, count: 32),
      conversationKeyVersion: "1", senderId: value)
  }
  #expect(sender?.description == "Invalid sender_id '\(value)': \(rule)")
  let participant = #expect(throws: XChatError.invalidInput(.participantUserId(value))) {
    try core.prepareConversationKeyChange(
      participants: [
        ConversationParticipantPublicKey(
          userId: value, identityPublicKey: TestVectors.string("identity_public_b64"),
          publicKeyVersion: "1")
      ],
      conversationId: "1111:2222", senderId: "1111", conversationKeyVersion: "2")
  }
  #expect(participant?.description == "Invalid public_keys user_id '\(value)': \(rule)")
}

/// Each of these is refused as a key version, though most are an integer
/// in digits: a leading zero or a sign is not canonical, a negative value
/// is no version, and a value past `Int64.max` does not fit. The
/// description states the whole rule for every version a call takes.
@Test(arguments: ["01", "00", "+1", "-1", "9223372036854775808"])
func keyVersionsAreDescribedByTheWholeRule(value: String) throws {
  let rule =
    "pass the key version as the X API returns it, a non-negative integer that fits in an "
    + "Int64, in decimal digits with no sign or leading zero (zero is '0')"
  let core = try sendingCore()
  let conversation = #expect(throws: XChatError.invalidInput(.conversationKeyVersion(value))) {
    try core.encryptMessage(
      text: "x", conversationId: "1111:2222", conversationKey: [UInt8](repeating: 1, count: 32),
      conversationKeyVersion: value, senderId: "1111")
  }
  #expect(conversation?.description == "Invalid conversation_key_version '\(value)': \(rule)")
  let participant = #expect(throws: XChatError.invalidInput(.participantKeyVersion(value))) {
    try core.prepareConversationKeyChange(
      participants: [
        ConversationParticipantPublicKey(
          userId: "2222", identityPublicKey: TestVectors.string("identity_public_b64"),
          publicKeyVersion: value)
      ],
      conversationId: "1111:2222", senderId: "1111", conversationKeyVersion: "2")
  }
  #expect(
    participant?.description == "Invalid public_keys public_key_version '\(value)': \(rule)")
  let publicKey = #expect(throws: XChatError.invalidInput(.publicKeyVersion(value))) {
    try core.setPublicKeyVersion(value)
  }
  #expect(publicKey?.description == "Invalid public key version '\(value)': \(rule)")
}

/// Zero, written "0", is a key version, as the description says, though
/// it is no user id.
@Test func zeroIsAKeyVersion() throws {
  let core = try sendingCore()
  try core.setPublicKeyVersion("0")
  let payload = try core.encryptMessage(
    text: "x", conversationId: "1111:2222", conversationKey: [UInt8](repeating: 1, count: 32),
    conversationKeyVersion: "0", senderId: "1111")
  #expect(payload.conversationKeyVersion == "0")
}

/// A rejected signature names the key it was checked under by the event's
/// sender and key version, the `userId` and `publicKeyVersion` of the
/// `SigningKeyEntry` to replace: a batch holds several senders' events,
/// and `decryptEvents` returns only the index of one that fails.
@Test func rejectedSignaturesNameTheSenderOfTheKey() throws {
  let sender = TestVectors.string("event_sender_id")
  let otherSender = TestVectors.string("message_key_sender_id")
  let keyVersion = TestVectors.string("event_signing_key_version")
  let events = [
    TestVectors.string("event_message_b64"), TestVectors.string("event_message_key_b64"),
  ]
  let keys = [
    TestVectors.string("event_conversation_key_version"): TestVectors.bytes(
      "conversation_key_b64"),
    TestVectors.string("message_key_conversation_key_version"): try Hex.decode(
      TestVectors.string("message_key_conversation_key_hex")),
  ]
  func decrypt(senderKey: String, otherSenderKey: String) -> DecryptEventsResult {
    XChatCore().decryptEvents(
      events, conversationKeys: keys,
      signingKeys: [
        SigningKeyEntry(userId: sender, publicKeyVersion: keyVersion, publicKey: senderKey),
        SigningKeyEntry(
          userId: otherSender, publicKeyVersion: keyVersion, publicKey: otherSenderKey),
      ])
  }
  let signingKey = TestVectors.string("signing_public_b64")
  // A P-256 public key, but not the one that signed.
  let otherKey = TestVectors.string("identity_public_b64")
  let notAKey = Base64.encodeStandard([0x04] + [UInt8](repeating: 0, count: 64))

  let verified = decrypt(senderKey: signingKey, otherSenderKey: signingKey)
  #expect(verified.errors.isEmpty)
  #expect(verified.events.count == 2)

  let mismatch = decrypt(senderKey: signingKey, otherSenderKey: otherKey)
  #expect(
    mismatch.errors == [
      1: .verification(
        .rejected(.message, .mismatch(senderId: otherSender, keyVersion: keyVersion)))
    ])
  #expect(mismatch.events.count == 1)

  let invalidKey = decrypt(senderKey: notAKey, otherSenderKey: signingKey)
  #expect(
    invalidKey.errors == [
      0: .verification(
        .rejected(.message, .invalidSigningPublicKey(senderId: sender, keyVersion: keyVersion)))
    ])
  #expect(invalidKey.events.count == 1)
}
