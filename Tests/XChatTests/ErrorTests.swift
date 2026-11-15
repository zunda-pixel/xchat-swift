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
/// event or key changes to decryptEvents.
@Test func sharedCasesDescribeTheFaultForEitherDirection() {
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

/// A missing conversation key lists the versions there were keys for,
/// which in decryptEvents include those adopted from the batch's key
/// changes, so the description does not say they were given.
@Test func missingKeysListTheVersionsThereWereKeysFor() {
  let missingKey = XChatError.decryption(
    .missingConversationKey(.quotedMessage, version: "2", available: ["1"]))
  #expect(
    missingKey.description
      == "The quoted message is encrypted under conversation-key version '2', and there was "
      + "no key for it; there were keys for versions 1")
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
/// whatever its case and role; what a nested value adds follows a colon,
/// as it would mid-sentence.
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
  .invalidInput(.noSequenceId(.quotedMessage)),
  .invalidInput(.quotedMessageNotEmbedded),
  .invalidInput(.quotedMessageInOtherConversation),
  .invalidInput(.emptyMediaHashKey),
  .invalidInput(.mediaHashKeyNotFound("h", available: [])),
  .invalidInput(.quotedMediaHashKey("h")),
  .invalidInput(.attachment(index: 0, .emptyURL)),
  .invalidState(.keysNotLoaded),
  .invalidState(.signingKeyNotLoaded),
  .invalidState(.signingKeyVersionNotSet),
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
      == "Invalid base64 byte: '!' (0x21)")
  #expect(
    XChatError.parse(.base64(.invalidByte(0xC3))).description == "Invalid base64 byte: 0xC3")
  #expect(XChatError.parse(.hex(.invalidByte(0x0A))).description == "Invalid hex byte: 0x0A")
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
  #expect(
    XChatError.parse(.base64(.invalidLength(5))).description
      == "Invalid base64 length: 5 characters, not counting '=', which no bytes encode to")
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
  #expect(
    XChatError.parse(.base64(.excessPadding(4))).description
      == "Invalid base64 padding: 4 '=', at most 2")
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
