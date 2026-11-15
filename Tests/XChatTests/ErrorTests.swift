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

/// Each case reports the kind the other chat-xdk bindings name it by.
@Test(arguments: [
  (XChatError.invalidInput(.noParticipants), "invalid_input"),
  (.invalidState(.signingKeyNotLoaded), "invalid_state"),
  (.parse(.base64(.dataAfterPadding)), "parse"),
  (.decryption(.authenticationFailed), "decryption"),
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
