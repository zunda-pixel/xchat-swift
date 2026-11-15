import Clibsodium

enum SecretStreamTag: UInt8, Sendable {
  case message = 0
  case push = 1
  case rekey = 2
  case final = 3
}

struct SecretStreamPush: Sendable {
  private var state: crypto_secretstream_xchacha20poly1305_state

  /// Starts a stream under a 32-byte key, which the caller has checked.
  static func start(key: [UInt8]) throws -> (header: [UInt8], stream: SecretStreamPush) {
    precondition(key.count == 32, "secretstream keys are 32 bytes")
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
    try push(plaintext, associatedData: associatedData, rawTag: tag.rawValue)
  }

  /// Pushes a frame with any tag byte. libsodium authenticates whatever tag
  /// a sender writes, so a reader must handle tags the format does not
  /// define; this writes them.
  mutating func push(
    _ plaintext: [UInt8], associatedData: [UInt8] = [], rawTag: UInt8
  ) throws -> [UInt8] {
    var frame = [UInt8](repeating: 0, count: plaintext.count + 17)
    let status = unsafe crypto_secretstream_xchacha20poly1305_push(
      &state, &frame, nil, plaintext, UInt64(plaintext.count),
      associatedData, UInt64(associatedData.count), rawTag)
    guard status == 0 else { throw XChatError.internalError(.streamEncryptionFailed) }
    return frame
  }
}

struct SecretStreamPull: Sendable {
  private var state: crypto_secretstream_xchacha20poly1305_state

  /// Starts reading a stream under a 32-byte key from its 24-byte header,
  /// both of which the caller has checked.
  init(header: [UInt8], key: [UInt8]) throws {
    precondition(key.count == 32, "secretstream keys are 32 bytes")
    precondition(header.count == 24, "secretstream headers are 24 bytes")
    guard sodiumReady else { throw XChatError.internalError(.sodiumInitializationFailed) }
    state = crypto_secretstream_xchacha20poly1305_state()
    // libsodium accepts any 24 bytes as a header, so a failure is its own.
    let status = unsafe crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key)
    guard status == 0 else { throw XChatError.internalError(.streamInitializationFailed) }
  }

  /// Decrypts one frame, advancing the stream only when it authenticates
  /// and carries a tag the format defines.
  mutating func pull(
    _ frame: [UInt8], associatedData: [UInt8] = []
  ) throws -> (plaintext: [UInt8], tag: SecretStreamTag) {
    guard frame.count >= 17 else { throw PrimitiveError.ciphertextTooShort }
    let count = frame.count - 17
    var plaintext = [UInt8](repeating: 0, count: max(1, count))
    var rawTag: UInt8 = 0
    var nextState = state
    let status = unsafe crypto_secretstream_xchacha20poly1305_pull(
      &nextState, &plaintext, nil, &rawTag, frame, UInt64(frame.count),
      associatedData, UInt64(associatedData.count))
    guard status == 0 else { throw PrimitiveError.authenticationFailed }
    guard let tag = SecretStreamTag(rawValue: rawTag) else {
      throw PrimitiveError.unknownStreamTag(rawTag)
    }
    state = nextState
    return (Array(plaintext.prefix(count)), tag)
  }
}
