/// What kind of failure an `XChatError` is. The names match the kinds the
/// other chat-xdk bindings report, in snake_case.
public enum ErrorKind: String, Sendable {
  /// A parameter is missing or invalid.
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

/// The single error type every SDK call throws. The case is the kind of
/// failure, and its value says exactly what went wrong, with the values
/// involved, so callers tell failures apart by matching cases.
public enum XChatError: Error, Sendable, Equatable {
  /// A parameter is missing or invalid.
  case invalidInput(InvalidInput)
  /// A value was neither passed nor available from the chat's state.
  case invalidState(InvalidState)
  /// Event or other wire data is malformed.
  case parse(ParseFailure)
  /// Ciphertext did not decrypt, or no key for it was available.
  case decryption(DecryptionFailure)
  /// A signature did not verify, or could not be verified while
  /// unverified events are rejected.
  case verification(VerificationFailure)
  /// A failure inside the SDK, such as a cryptographic primitive failing.
  case internalError(InternalFailure)

  /// The kind of failure, named as the other chat-xdk bindings report it.
  public var kind: ErrorKind {
    switch self {
    case .invalidInput: .invalidInput
    case .invalidState: .invalidState
    case .parse: .parse
    case .decryption: .decryption
    case .verification: .verification
    case .internalError: .internalError
    }
  }
}

// MARK: Invalid input

extension XChatError {
  /// What about a parameter is invalid.
  public enum InvalidInput: Sendable, Equatable {
    // Keys

    /// A conversation key is not 32 bytes; the value is its length.
    case conversationKeyLength(Int)
    /// A key passed to `encryptFileWithKey` or `decryptFileWithKey` is not
    /// 32 bytes; the value is its length.
    case fileKeyLength(Int)
    /// A secretstream header is not 24 bytes; the value is its length.
    case streamHeaderLength(Int)
    /// A public key is not a P-256 point in compressed SEC1, uncompressed
    /// SEC1, or SPKI DER.
    case publicKey
    /// A public key decodes but is not the canonical P-256
    /// SubjectPublicKeyInfo, such as one whose algorithm names another
    /// curve.
    case subjectPublicKeyInfo
    /// A private key is not a 32-byte P-256 scalar in `[1, n-1]`.
    case privateKey
    /// The ephemeral public key an ECIES ciphertext starts with is not a
    /// P-256 point.
    case ephemeralPublicKey
    /// The loaded keys have no public key version to sign under: import
    /// them with their version, or set it.
    case signingKeyVersionNotSet

    // Ids and versions, with the value that was passed

    /// A public key version is not a non-negative integer in canonical
    /// decimal form, as the X API returns it.
    case publicKeyVersion(String)
    /// `sender_id` is not a positive integer in canonical decimal form.
    case senderId(String)
    /// `conversation_key_version` is not a non-negative integer in
    /// canonical decimal form, as the X API returns it.
    case conversationKeyVersion(String)
    /// A participant's user id is not a positive integer in canonical
    /// decimal form.
    case participantUserId(String)
    /// A participant's public key version is not a non-negative integer in
    /// canonical decimal form.
    case participantKeyVersion(String)

    // Building events

    /// A conversation-key change was asked for with no participants.
    case noParticipants
    /// No conversation id was passed, and the participants are not two
    /// distinct users, so no one-to-one id derives from them. The value is
    /// the number of distinct users.
    case conversationIdNotDerivable(distinctUsers: Int)
    /// A component the signature covers contains a comma, which would make
    /// the comma-joined payload ambiguous.
    case signaturePayloadContainsComma
    /// An entity's offsets are not a range of the text's UTF-8 bytes.
    case entityRange(start: Int32, end: Int32)
    /// The attachment descriptor at `index` is invalid.
    case attachment(index: Int, InvalidAttachment)
    /// The target message's sequence id is empty.
    case emptyTargetSequenceId
    /// The reaction emoji is empty.
    case emptyReactionEmoji

    // Messages and their media

    /// The event is not a message event.
    case notMessageEvent(MessageRole)
    /// The message is an edit, which carries neither the edited message's
    /// text nor its media.
    case messageIsEdit(MessageRole)
    /// The message is a reaction, read marker, or another entry that is not
    /// a text message.
    case notTextMessage(MessageRole)
    /// The message is not encrypted, so neither is its media.
    case notEncrypted(MessageRole)
    /// The message event carries no contents.
    case noContents(MessageRole)
    /// The message event carries no message id, which a per-message key
    /// derives its attachments' keys from.
    case noMessageId(MessageRole)
    /// The message event carries no sequence id.
    case noSequenceId(MessageRole)
    /// The key a reply carries for the message it quotes is not 32 bytes;
    /// the value is its length.
    case carriedMessageKeyLength(Int)
    /// A reply does not embed the message it quotes, so that message cannot
    /// be opened through the reply.
    case quotedMessageNotEmbedded
    /// The quoted message belongs to a different conversation than the
    /// reply.
    case quotedMessageInOtherConversation
    /// The media hash key is empty.
    case emptyMediaHashKey
    /// The media hash key is not among the message's media. `available`
    /// lists the message's media hash keys in order; it is empty when the
    /// message has no media.
    case mediaHashKeyNotFound(String, available: [String])
    /// The media hash key names media the reply quotes: its file belongs to
    /// the quoted message and was uploaded with it, so there is nothing to
    /// encrypt.
    case quotedMediaHashKey(String)

    // Streaming file encryption

    /// The file encryptor was used after `finish`.
    case fileEncryptorFinished
    /// The file decryptor was used after `finish`.
    case fileDecryptorFinished
  }

  /// What about an attachment descriptor is invalid.
  public enum InvalidAttachment: Sendable, Equatable {
    /// A media attachment's media hash key is empty.
    case emptyMediaHashKey
    /// A media attachment's width or height is negative.
    case negativeDimensions
    /// A media attachment's file size is not positive.
    case nonPositiveFilesize
    /// A media attachment's filename is empty.
    case emptyFilename
    /// A media attachment's media type is none the protocol defines; the
    /// value is the one passed.
    case unknownMediaType(Int32)
    /// A media attachment's plaintext SHA-256 is not the base64 of 32
    /// bytes.
    case plaintextSHA256
    /// A URL attachment's URL is empty.
    case emptyURL
    /// A post attachment has neither a rest id nor a post URL.
    case postWithoutReference
    /// A URL card image's media hash key is empty.
    case imageEmptyMediaHashKey
    /// A URL card image's file size is not positive.
    case imageNonPositiveFilesize
    /// A URL card image's filename is empty.
    case imageEmptyFilename
    /// A URL card image's width is negative.
    case imageNegativeWidth
    /// A URL card image's height is negative.
    case imageNegativeHeight
  }

  /// Which message an error is about: the message whose event was passed,
  /// or the message a reply quotes.
  public enum MessageRole: Sendable, Equatable {
    case message
    case quotedMessage
  }
}

// MARK: Invalid state

extension XChatError {
  /// What the chat's state lacks.
  public enum InvalidState: Sendable, Equatable {
    /// No keys are loaded: import keys first.
    case keysNotLoaded
    /// No signing key is loaded.
    case signingKeyNotLoaded
  }
}

// MARK: Parse

extension XChatError {
  /// What is malformed, and where.
  public enum ParseFailure: Sendable, Equatable {
    /// Base64 does not decode.
    case base64(Base64Failure)
    /// Hex does not decode.
    case hex(HexFailure)
    /// An event's base64 does not decode.
    case eventBase64(Base64Failure)
    /// An event's Thrift encoding is malformed.
    case event(ThriftFailure)
    /// A message's decrypted contents are malformed Thrift.
    case messageContents(ThriftFailure)
  }

  /// Why base64 does not decode.
  public enum Base64Failure: Sendable, Equatable {
    /// Data follows `=` padding.
    case dataAfterPadding
    /// A byte is not in the alphabet; the value is that byte.
    case invalidCharacter(UInt8)
    /// The length, padding included, is not a base64 length; the value is
    /// that length.
    case invalidLength(Int)
  }

  /// Why hex does not decode.
  public enum HexFailure: Sendable, Equatable {
    /// The input has an odd number of bytes; the value is that number.
    case oddLength(Int)
    /// The input has a byte that is not a hex digit; the value is the
    /// input.
    case invalidCharacter(in: String)
  }

  /// Why a Thrift binary-protocol encoding is malformed.
  public enum ThriftFailure: Sendable, Equatable {
    /// The input ends inside a value.
    case unexpectedEnd
    /// A type byte names no Thrift type; the value is that byte.
    case unknownType(UInt8)
    /// A binary value or container declares a negative size.
    case negativeSize(ThriftType, Int32)
    /// A binary value or container declares a size over the limit.
    case sizeExceedsMaximum(ThriftType, Int32, maximum: Int)
    /// The containers read so far hold more elements in total than the
    /// limit.
    case totalElementsExceedMaximum(UInt64, maximum: UInt64)
    /// Skipped values nest deeper than the limit.
    case nestingTooDeep(maximum: Int)
    /// A string is not UTF-8.
    case invalidUTF8
    /// A field's wire type is not the type its struct declares.
    case fieldType(field: String, id: Int16, actual: ThriftType, expected: ThriftType)
    /// A list field's element type is not the type its struct declares.
    case listElementType(field: String, actual: ThriftType, expected: ThriftType)
    /// A map field does not map strings to strings.
    case mapTypes(field: String, key: ThriftType, value: ThriftType)
    /// A message's attachment sets none of its variants.
    case messageAttachmentWithoutVariant
    /// A reply preview's attachment sets none of its variants.
    case previewAttachmentWithoutVariant
  }
}

// MARK: Decryption

extension XChatError {
  /// Why ciphertext did not decrypt.
  public enum DecryptionFailure: Sendable, Equatable {
    /// The ciphertext did not authenticate: it was encrypted under another
    /// key, or it is corrupted. Authenticated encryption cannot tell the
    /// two apart, so one case covers both.
    case authenticationFailed
    /// The ciphertext is shorter than its format's fixed overhead (nonce,
    /// tag, or ephemeral key), so it is no ciphertext of that format.
    case ciphertextTooShort
    /// libsodium refused a secretstream header.
    case invalidStreamHeader
    /// A secretstream frame authenticated but carries a tag the format does
    /// not define; the value is that tag.
    case unknownStreamTag(UInt8)
    /// An encrypted file did not decrypt. `mediaHashKey` names the media
    /// when the file was opened as a message's media; it is nil for a file
    /// under a key the caller holds.
    case file(FileFault, mediaHashKey: String?)
    /// A message is encrypted under a conversation-key version no key was
    /// given for. `available` lists the versions there were keys for,
    /// sorted.
    case missingConversationKey(version: String, available: [String])
    /// A per-message key derives from the sender id in decimal digits; the
    /// value is the sender id the event carries.
    case nonNumericSenderId(String)
    /// A per-message key derives from the event's sender id and message
    /// id, and the event lacks one of them.
    case missingSenderOrMessageId
  }

  /// Why an encrypted file's bytes did not decrypt.
  public enum FileFault: Sendable, Equatable {
    /// A frame with more of the file after it did not authenticate: the
    /// bytes are corrupted, or they are another file's (encrypted under
    /// another key). As with `DecryptionFailure.authenticationFailed`, the
    /// two cannot be told apart.
    case authenticationFailed
    /// The last frame did not authenticate. Bytes cut short inside that
    /// frame fail the same way, so besides being corrupted or another
    /// file's, the bytes may be truncated.
    case lastFrameAuthenticationFailed
    /// Data follows the file's final frame.
    case dataAfterFinalFrame
    /// The bytes end before the file's final frame, or inside its 24-byte
    /// header.
    case truncated
  }
}

// MARK: Verification

extension XChatError {
  /// Why a signature did not verify.
  public enum VerificationFailure: Sendable, Equatable {
    /// A signature is not a raw 64-byte `r || s` ECDSA P-256 signature.
    case malformedSignature
    /// An event's signature could not be checked: the event carries none,
    /// or no signing key was given at its key version. Thrown while
    /// unverified events are rejected.
    case unverifiable(SignedEvent)
    /// An event's signature was checked and does not hold.
    case rejected(SignedEvent, SignatureRejection)
  }

  /// The kind of event whose signature an error is about.
  public enum SignedEvent: Sendable, Equatable {
    case message
    case keyChange
  }

  /// Why an event's signature was rejected.
  public enum SignatureRejection: Sendable, Equatable {
    /// The signature's version is missing or not an integer.
    case missingSignatureVersion
    /// The signature's version is below the lowest one accepted.
    case signatureVersionTooOld(Int32, minimum: Int32)
    /// The signature's version is above the highest one supported.
    case signatureVersionUnsupported(Int32, maximum: Int32)
    /// The signature does not match the payload rebuilt from the event,
    /// under the signing key at `keyVersion`.
    case mismatch(keyVersion: String, payloadLength: Int)
    /// The signature is not a raw 64-byte `r || s` ECDSA P-256 signature.
    case malformedSignature
    /// The signing key at the event's key version is not a P-256 public
    /// key.
    case invalidSigningPublicKey
  }
}

// MARK: Internal

extension XChatError {
  /// What failed inside the SDK.
  public enum InternalFailure: Sendable, Equatable {
    /// HKDF was asked for more output than it can derive.
    case hkdfLengthExceedsMaximum(Int, maximum: Int)
    /// libsodium did not initialize.
    case sodiumInitializationFailed
    /// libsodium did not start a secretstream.
    case streamInitializationFailed
    /// libsodium did not encrypt a secretstream frame.
    case streamEncryptionFailed
    /// libsodium did not encrypt a secretbox.
    case secretboxEncryptionFailed
    /// The loaded signing key is not a P-256 private key.
    case invalidSigningPrivateKey
    /// An error that is not an `XChatError` reached a result that holds
    /// only `XChatError`s. Nothing in the SDK is known to raise one.
    case unexpected
  }
}

extension XChatError {
  /// `error` when it is an `XChatError`; otherwise `.unexpected`, for
  /// results that hold only `XChatError`s. The other error is not kept:
  /// holding an `any Error` would keep `XChatError` from being `Equatable`.
  init(_ error: any Error) {
    self = error as? XChatError ?? .internalError(.unexpected)
  }
}
