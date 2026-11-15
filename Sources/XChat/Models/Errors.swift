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
///
/// Later versions add cases as the SDK learns to tell more failures apart,
/// at every level of nesting. Match the cases you handle and leave the
/// rest to `default`, which `description` describes. A switch that lists
/// every case ends with `@unknown default` instead: the package is built
/// without library evolution, so the compiler warns that a `default`
/// after every case will never be executed, while `@unknown default`
/// compiles cleanly and turns a case a later version adds into a warning
/// rather than an error.
public enum XChatError: Error, Sendable, Hashable {
  /// A parameter is missing or invalid.
  case invalidInput(InputFailure)
  /// A value was neither passed nor available from the chat's state.
  case invalidState(StateFailure)
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
  public enum InputFailure: Sendable, Hashable {
    // Keys

    /// A conversation key is not 32 bytes; the value is its length.
    case conversationKeyLength(Int)
    /// A key passed to `encryptFileWithKey` or `decryptFileWithKey` is not
    /// 32 bytes; the value is its length.
    case fileKeyLength(Int)
    /// A private key is not a 32-byte P-256 scalar in `[1, n-1]`.
    case privateKey

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
    /// The identity public key of the participant `userId` is not the
    /// base64 of a P-256 public key in compressed SEC1, uncompressed SEC1,
    /// or canonical SPKI DER.
    case participantIdentityKey(userId: String)

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
    case attachment(index: Int, AttachmentFailure)
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
  public enum AttachmentFailure: Sendable, Hashable {
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
  public enum MessageRole: Sendable, Hashable {
    case message
    case quotedMessage
  }
}

// MARK: Invalid state

extension XChatError {
  /// What the chat's state lacks.
  public enum StateFailure: Sendable, Hashable {
    /// No keys are loaded: import keys first.
    case keysNotLoaded
    /// No signing key is loaded.
    case signingKeyNotLoaded
    /// The loaded keys have no public key version to sign under: import
    /// them with their version, or set it with `setPublicKeyVersion`.
    case signingKeyVersionNotSet
  }
}

// MARK: Parse

extension XChatError {
  /// What is malformed, and where.
  public enum ParseFailure: Sendable, Hashable {
    /// Input to `Base64.decodeStandard` or `Base64.decodeURLSafe` does not
    /// decode.
    case base64(Base64Failure)
    /// Input to `Hex.decode` does not decode.
    case hex(HexFailure)
    /// An event does not decode.
    case event(EventFailure)
    /// The decrypted contents of the message the role names are
    /// malformed Thrift. Opening a reply's media reads both the reply and
    /// the message it quotes, so the role tells them apart.
    case messageContents(MessageRole, ThriftFailure)
  }

  /// Why an event does not decode: events travel as the base64 of their
  /// Thrift encoding.
  public enum EventFailure: Sendable, Hashable {
    /// The base64 does not decode.
    case base64(Base64Failure)
    /// The Thrift encoding is malformed.
    case thrift(ThriftFailure)
  }

  /// Why base64 does not decode.
  public enum Base64Failure: Sendable, Hashable {
    /// Data follows `=` padding.
    case dataAfterPadding
    /// A byte is not in the alphabet; the value is that byte.
    case invalidCharacter(UInt8)
    /// The length, padding included, is not a base64 length; the value is
    /// that length.
    case invalidLength(Int)
  }

  /// Why hex does not decode.
  public enum HexFailure: Sendable, Hashable {
    /// The input has an odd number of bytes; the value is that number.
    case oddLength(Int)
    /// A byte is not a hex digit; the value is that byte. The rest of the
    /// input is not kept, since it may be a key.
    case invalidCharacter(UInt8)
  }

  /// Why a Thrift binary-protocol encoding is malformed.
  public enum ThriftFailure: Sendable, Hashable {
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
  public enum DecryptionFailure: Sendable, Hashable {
    /// A message's contents did not decrypt under `key`, the key the SDK
    /// resolved for that message from the arguments.
    case messageContents(MessageRole, ContentsFailure, key: ContentsKey)
    /// An encrypted file did not decrypt. `mediaHashKey` names the media
    /// when the file was opened as a message's media; it is nil for a file
    /// under a key the caller holds.
    case file(FileFailure, mediaHashKey: String?)
    /// A message is encrypted under a conversation-key version no key was
    /// given for. `available` lists the versions there were keys for,
    /// sorted.
    case missingConversationKey(MessageRole, version: String, available: [String])
    /// The keys of a message with per-message keys derive from its event's
    /// sender id and message id, and the event lacks one it needs.
    case missingSenderOrMessageId(MessageRole)
    /// A per-message key derives from the sender id as a 64-bit integer,
    /// and the event's sender id does not parse as one: it is not decimal
    /// digits after an optional sign, or it is out of range. The value is
    /// that sender id.
    case nonNumericSenderId(MessageRole, String)
  }

  /// Why a message's contents did not decrypt.
  public enum ContentsFailure: Sendable, Hashable {
    /// The contents did not authenticate: the key is not the one they
    /// were encrypted under, or they are corrupted. Authenticated
    /// encryption cannot tell the two apart.
    case authenticationFailed
    /// The contents are shorter than a nonce and tag, so they are no
    /// encrypted contents.
    case ciphertextTooShort
    /// The key is not 32 bytes; the value is its length. Only a message
    /// encrypted under its conversation key itself reports this: a
    /// per-message key is derived to 32 bytes from a key of any length,
    /// and then fails to authenticate. The key a sending call sends under
    /// is checked before any message is opened, as
    /// `InputFailure.conversationKeyLength`, so this is about a key given
    /// for opening received messages.
    case keyLength(Int)
  }

  /// Where the key a message's contents were opened with came from.
  public enum ContentsKey: Sendable, Hashable {
    /// The conversation key given for `version`, the version the message
    /// is encrypted under, or the per-message key derived from it.
    case conversationKey(version: String)
    /// The per-message key a reply carries for the message it quotes, used
    /// because no conversation key was given for `version`, the version
    /// the quoted message is encrypted under.
    case carriedByReply(version: String)
  }

  /// Why an encrypted file's bytes did not decrypt.
  public enum FileFailure: Sendable, Hashable {
    /// A frame with more of the file after it did not authenticate: the
    /// bytes are corrupted, or they are another file's (encrypted under
    /// another key). As with `ContentsFailure.authenticationFailed`, the
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
    /// A frame authenticated but carries a tag secretstream does not
    /// define, 4 or above; the value is that tag. Only a sender holding
    /// the key can write one. Frames tagged push (1) or rekey (2), which
    /// secretstream defines, decrypt as the file's other frames.
    case unknownTag(UInt8)
  }
}

// MARK: Verification

extension XChatError {
  /// Why a signature did not verify.
  public enum VerificationFailure: Sendable, Hashable {
    /// An event's signature could not be checked: the event carries none,
    /// or no signing key was given at its key version. Thrown while
    /// unverified events are rejected.
    case unverifiable(SignedEvent)
    /// An event's signature was checked and does not hold.
    case rejected(SignedEvent, SignatureFailure)
  }

  /// The kind of event whose signature an error is about.
  public enum SignedEvent: Sendable, Hashable {
    case message
    case keyChange
  }

  /// Why an event's signature was rejected.
  public enum SignatureFailure: Sendable, Hashable {
    /// The signature's version is missing or not an integer.
    case missingSignatureVersion
    /// The signature's version is below the lowest one accepted.
    case signatureVersionTooOld(Int32, minimum: Int32)
    /// The signature's version is above the highest one supported.
    case signatureVersionUnsupported(Int32, maximum: Int32)
    /// The signature does not match the payload rebuilt from the event,
    /// under the signing key at `keyVersion`.
    case mismatch(keyVersion: String)
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
  public enum InternalFailure: Sendable, Hashable {
    /// libsodium did not initialize.
    case sodiumInitializationFailed
    /// libsodium did not start a secretstream.
    case streamInitializationFailed
    /// libsodium did not encrypt a secretstream frame.
    case streamEncryptionFailed
    /// libsodium did not encrypt a secretbox.
    case secretboxEncryptionFailed
    /// Swift Crypto did not agree a P-256 shared secret for ECIES.
    case keyAgreementFailed
    /// Swift Crypto did not encrypt with AES-GCM for ECIES.
    case gcmEncryptionFailed
    /// Swift Crypto did not sign with the loaded signing key.
    case signingFailed
    /// An error that is not an `XChatError` reached a result that holds
    /// only `XChatError`s; the value is that error's description. Nothing
    /// in the SDK is known to raise one.
    case unexpected(String)
  }
}

extension XChatError {
  /// `error` when it is an `XChatError`; otherwise `.unexpected` with the
  /// other error's description, for results that hold only `XChatError`s.
  /// The other error itself is not kept: holding an `any Error` would keep
  /// `XChatError` from being `Hashable`.
  init(_ error: any Error) {
    self = error as? XChatError ?? .internalError(.unexpected(String(describing: error)))
  }
}
