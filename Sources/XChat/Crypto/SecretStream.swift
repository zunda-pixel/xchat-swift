import Clibsodium

enum SecretStreamTag: UInt8, Sendable {
  case message = 0
  case push = 1
  case rekey = 2
  case final = 3
}

struct SecretStreamPush: Sendable {
  private var state: crypto_secretstream_xchacha20poly1305_state

  static func start(key: [UInt8]) throws -> (header: [UInt8], stream: SecretStreamPush) {
    guard key.count == 32 else {
      throw XChatError.invalidInput(.conversationKeyLength(key.count))
    }
    guard sodiumReady else { throw XChatError.internalError(.sodiumInitializationFailed) }
    var state = crypto_secretstream_xchacha20poly1305_state()
    var header = [UInt8](repeating: 0, count: 24)
    let status = unsafe crypto_secretstream_xchacha20poly1305_init_push(&state, &header, key)
    guard status == 0 else { throw XChatError.internalError(.streamInitializationFailed) }
    return (header, SecretStreamPush(state: state))
  }

  mutating func push(
    _ plaintext: [UInt8], associatedData: [UInt8] = [], tag: SecretStreamTag
  ) throws -> [UInt8] {
    var frame = [UInt8](repeating: 0, count: plaintext.count + 17)
    let status = unsafe crypto_secretstream_xchacha20poly1305_push(
      &state, &frame, nil, plaintext, UInt64(plaintext.count),
      associatedData, UInt64(associatedData.count), tag.rawValue)
    guard status == 0 else { throw XChatError.internalError(.streamEncryptionFailed) }
    return frame
  }
}

struct SecretStreamPull: Sendable {
  private var state: crypto_secretstream_xchacha20poly1305_state

  init(header: [UInt8], key: [UInt8]) throws {
    guard key.count == 32 else {
      throw XChatError.invalidInput(.conversationKeyLength(key.count))
    }
    guard header.count == 24 else {
      throw XChatError.invalidInput(.streamHeaderLength(header.count))
    }
    guard sodiumReady else { throw XChatError.internalError(.sodiumInitializationFailed) }
    state = crypto_secretstream_xchacha20poly1305_state()
    let status = unsafe crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key)
    guard status == 0 else { throw XChatError.decryption(.invalidStreamHeader) }
  }

  mutating func pull(
    _ frame: [UInt8], associatedData: [UInt8] = []
  ) throws -> (plaintext: [UInt8], tag: SecretStreamTag) {
    guard frame.count >= 17 else { throw XChatError.decryption(.ciphertextTooShort) }
    let count = frame.count - 17
    var plaintext = [UInt8](repeating: 0, count: max(1, count))
    var rawTag: UInt8 = 0
    var nextState = state
    let status = unsafe crypto_secretstream_xchacha20poly1305_pull(
      &nextState, &plaintext, nil, &rawTag, frame, UInt64(frame.count),
      associatedData, UInt64(associatedData.count))
    guard status == 0 else { throw XChatError.decryption(.authenticationFailed) }
    guard let tag = SecretStreamTag(rawValue: rawTag) else {
      throw XChatError.decryption(.unknownStreamTag(rawTag))
    }
    state = nextState
    return (Array(plaintext.prefix(count)), tag)
  }
}
