import Foundation

/// What kind of failure an `XChatError` is. The names match the kinds the
/// other chat-xdk bindings report, in snake_case.
public enum ErrorKind: String, Sendable {
  /// A parameter is missing or invalid; the message names it.
  case invalidInput = "invalid_input"
  /// A value was neither passed nor available from the chat's state.
  case invalidState = "invalid_state"
  /// Event or other wire data is malformed.
  case parse
  /// Ciphertext did not decrypt, or no key for it was available.
  case decryption
  /// A signature did not verify, or could not be verified while
  /// unverified events are rejected.
  case verification
  /// A failure inside the SDK, such as a cryptographic primitive failing.
  case internalError = "internal"
}

/// The single error type every SDK call throws. `kind` says what went
/// wrong in machine-readable form; `message` says what to pass instead.
public struct XChatError: Error, Sendable, CustomStringConvertible {
  public let kind: ErrorKind
  public let message: String

  init(kind: ErrorKind, message: String) {
    self.kind = kind
    self.message = message
  }

  public var description: String { message }

  public var localizedDescription: String { message }

  static func invalidInput(_ message: String) -> XChatError {
    XChatError(kind: .invalidInput, message: message)
  }

  static func invalidState(_ message: String) -> XChatError {
    XChatError(kind: .invalidState, message: message)
  }

  static func parse(_ message: String) -> XChatError {
    XChatError(kind: .parse, message: message)
  }

  static func decryption(_ message: String) -> XChatError {
    XChatError(kind: .decryption, message: message)
  }

  static func verification(_ message: String) -> XChatError {
    XChatError(kind: .verification, message: message)
  }

  static func internalError(_ message: String) -> XChatError {
    XChatError(kind: .internalError, message: message)
  }
}
