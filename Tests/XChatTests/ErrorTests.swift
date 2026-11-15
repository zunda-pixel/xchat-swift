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
  #expect(anyError.localizedDescription == "keys are not loaded: import keys first")
  #expect(anyError.localizedDescription == String(describing: anyError))

  let withValue: any Error = XChatError.invalidInput(.conversationKeyLength(31))
  #expect(withValue.localizedDescription == "Conversation key must be 32 bytes, got 31")
}

/// The debug description is the case to match, not the English sentence,
/// and nested values print as their cases rather than as sentence
/// fragments.
@Test func debugDescriptionShowsTheCase() {
  let error = XChatError.invalidInput(.conversationKeyLength(31))
  #expect(String(reflecting: error) == "XChatError.invalidInput(.conversationKeyLength(31))")
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
      == "media_hash_key 'h' is not in the message, whose media hash keys are a, b")
  let noMedia = XChatError.invalidInput(.mediaHashKeyNotFound("h", available: []))
  #expect(noMedia.description == "media_hash_key 'h' is not in the message, which has no media")
  let missingKey = XChatError.decryption(
    .missingConversationKey(.quotedMessage, version: "2", available: ["1"]))
  #expect(
    missingKey.description
      == "the quoted message is encrypted under conversation-key version '2', and no key was "
      + "given for it; keys were given for versions 1")
}

/// A message's contents that do not decrypt are described with the message
/// and the key they were opened with.
@Test func contentsFailuresNameTheMessageAndKey() {
  let wrongKey = XChatError.decryption(
    .messageContents(.quotedMessage, .authenticationFailed, key: .carriedByReply(version: "2")))
  #expect(
    wrongKey.description
      == "the contents of the quoted message do not decrypt under the key the reply carries "
      + "for it (no conversation key was given for version '2'): it is not the key they were "
      + "encrypted under, or they are corrupted")
  let shortKey = XChatError.decryption(
    .messageContents(.message, .keyLength(31), key: .conversationKey(version: "1")))
  #expect(
    shortKey.description
      == "the conversation key for version '1' is 31 bytes, not 32, so it cannot decrypt the "
      + "contents of the message")
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
  #expect(throws: XChatError.parse(.hex(.invalidCharacter(UInt8(ascii: "g"))))) {
    try Hex.decode("00ff0g")
  }
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
