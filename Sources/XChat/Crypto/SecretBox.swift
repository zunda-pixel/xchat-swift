import Clibsodium

/// NaCl secretbox with detached ciphertext and authentication tag.
struct XSalsa20Poly1305: Sendable {
  static let nonceSize = 24
  static let tagSize = 16

  private let key: [UInt8]

  init(key: [UInt8]) {
    precondition(key.count == 32)
    self.key = key
  }

  func encryptDetached(
    nonce: [UInt8], plaintext: [UInt8]
  ) throws -> (ciphertext: [UInt8], tag: [UInt8]) {
    // Callers draw a fresh 24-byte nonce, so another length is a bug, as a
    // key of another length is for `init`.
    precondition(nonce.count == Self.nonceSize)
    guard sodiumReady else { throw XChatError.internalError(.sodiumInitializationFailed) }
    var ciphertext = [UInt8](repeating: 0, count: max(1, plaintext.count))
    var tag = [UInt8](repeating: 0, count: Self.tagSize)
    let status = unsafe crypto_secretbox_detached(
      &ciphertext, &tag, plaintext, UInt64(plaintext.count), nonce, key)
    guard status == 0 else { throw XChatError.internalError(.secretboxEncryptionFailed) }
    return (Array(ciphertext.prefix(plaintext.count)), tag)
  }

  func decryptDetached(nonce: [UInt8], ciphertext: [UInt8], tag: [UInt8]) throws -> [UInt8] {
    guard sodiumReady else { throw XChatError.internalError(.sodiumInitializationFailed) }
    // A nonce or tag of another length is not the one this ciphertext was
    // sealed with.
    guard nonce.count == Self.nonceSize, tag.count == Self.tagSize else {
      throw ContentsError(.authenticationFailed)
    }
    var plaintext = [UInt8](repeating: 0, count: max(1, ciphertext.count))
    let status = unsafe crypto_secretbox_open_detached(
      &plaintext, ciphertext, tag, UInt64(ciphertext.count), nonce, key)
    guard status == 0 else { throw ContentsError(.authenticationFailed) }
    return Array(plaintext.prefix(ciphertext.count))
  }
}

/// Encrypts a message payload with a fresh random nonce.
///
/// Wire format: nonce (24) || tag (16) || ciphertext.
func encryptMessage(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
  guard key.count == 32 else {
    throw XChatError.invalidInput(.conversationKeyLength(key.count))
  }
  let cipher = XSalsa20Poly1305(key: key)
  var nonce = [UInt8](repeating: 0, count: XSalsa20Poly1305.nonceSize)
  for i in nonce.indices {
    nonce[i] = UInt8.random(in: 0...255)
  }
  let (ciphertext, tag) = try cipher.encryptDetached(nonce: nonce, plaintext: plaintext)
  return nonce + tag + ciphertext
}

/// What `decryptMessage` throws when contents do not open. Only its callers
/// know whose contents they were and where the key came from, so they wrap
/// the failure in `XChatError.DecryptionFailure.messageContents`; see
/// `decryptContents`.
struct ContentsError: Error {
  var failure: XChatError.ContentsFailure

  init(_ failure: XChatError.ContentsFailure) {
    self.failure = failure
  }
}

/// Decrypts a message payload in the wire format above.
func decryptMessage(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
  // Minimum size: nonce (24) + tag (16) = 40 bytes.
  guard ciphertext.count >= XSalsa20Poly1305.nonceSize + XSalsa20Poly1305.tagSize else {
    throw ContentsError(.ciphertextTooShort)
  }
  guard key.count == 32 else {
    throw ContentsError(.keyLength(key.count))
  }
  let nonceSize = XSalsa20Poly1305.nonceSize
  let tagSize = XSalsa20Poly1305.tagSize
  let cipher = XSalsa20Poly1305(key: key)
  return try cipher.decryptDetached(
    nonce: Array(ciphertext[0..<nonceSize]),
    ciphertext: Array(ciphertext[(nonceSize + tagSize)...]),
    tag: Array(ciphertext[nonceSize..<nonceSize + tagSize]))
}

/// Decrypts the contents of the message `role` names with `key`, reporting
/// contents that do not open as
/// `XChatError.decryption(.messageContents(role, failure, key: source))`,
/// where `source` says where `key` came from.
func decryptContents(
  _ contents: [UInt8],
  key: [UInt8],
  of role: XChatError.MessageRole,
  from source: XChatError.ContentsKey
) throws -> [UInt8] {
  do {
    return try decryptMessage(key: key, ciphertext: contents)
  } catch let error as ContentsError {
    throw XChatError.decryption(.messageContents(role, error.failure, key: source))
  }
}
