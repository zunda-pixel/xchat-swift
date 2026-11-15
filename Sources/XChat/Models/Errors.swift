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
  ///
  /// An event passed to a call is a parameter, and so is a message it
  /// embeds. A message that is well formed but not one the call can use is
  /// reported here, whoever wrote it, by a case that names the message. A
  /// received reply's quoted message is reported here when the reply does
  /// not embed it, or when it is in another conversation, not a message
  /// event, not encrypted, without contents, an edit, or not a text
  /// message. The event `encryptReply` is given to quote is reported by the
  /// same cases for the reasons the two share: another conversation, not a
  /// message event, no contents, an edit, not a text message.
  /// `encryptReply` quotes an unencrypted message too, and instead needs
  /// the quoted event's sequence id (`quotedMessageWithoutSequenceId`).
  /// Bytes in either message that do not decode are `parse`, and contents
  /// that do not decrypt are `decryption`.
  public enum InputFailure: Sendable, Hashable {
    // Keys

    /// The conversation key a send or an outgoing file is made under is
    /// not 32 bytes; the value is its length.
    case conversationKeyLength(Int)
    /// A file's key is not 32 bytes; the value is its length. It is the key
    /// passed to `encryptFileWithKey`, `decryptFileWithKey`, or to
    /// `FileEncryptor` or `FileDecryptor` directly, even when that key is
    /// a conversation key, such as the key of a group's avatar image.
    case fileKeyLength(Int)
    /// A private key passed to `importKeys` is not a 32-byte P-256 scalar
    /// in `[1, n-1]`; the value says which of the two keys it is.
    case privateKey(KeyPurpose)

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
    /// The conversation id contains a comma. The signature covers the
    /// conversation id among other components joined with commas, so a
    /// comma would make the signed payload ambiguous. The other components
    /// are ids and versions in canonical decimal form, a message id the SDK
    /// mints, and base64, so the conversation id is the only one that can
    /// hold a comma. Sends and key changes check it with their other ids
    /// and versions, before what they build.
    case conversationIdContainsComma(String)

    // Building events

    /// A conversation-key change was asked for with no participants.
    case noParticipants
    /// No conversation id, or an empty one, was passed, and the
    /// participants are not two distinct users, so no one-to-one id derives
    /// from them. The value is the number of distinct users.
    case conversationIdNotDerivable(distinctUsers: Int)
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
    /// The event `encryptReply` is given to quote carries no sequence id,
    /// which the reply names it by. Only `encryptReply` needs one, so this
    /// case names no `MessageRole`.
    case quotedMessageWithoutSequenceId
    /// A reply does not embed the message it quotes, so that message cannot
    /// be opened through the reply.
    case quotedMessageNotEmbedded
    /// The quoted message belongs to a different conversation than the
    /// reply.
    case quotedMessageInOtherConversation
    /// The media hash key is empty.
    case emptyMediaHashKey
    /// The media hash key is not among the media the call can use.
    /// `available` lists the media hash keys it can, in order: the
    /// message's own, then, when receiving (`decryptFile`, `fileDecryptor`)
    /// a reply whose quoted message the call can open, that message's. A
    /// sending call (`encryptFile`, `fileEncryptor`) encrypts only the
    /// message's own files, so there it lists only those. It is empty when
    /// there are none.
    ///
    /// When a received reply's quoted message cannot be opened (for
    /// example, no key was given for it, or the reply does not embed it),
    /// `available` lists only the reply's own media: the media hash keys
    /// the reply's preview shows are written by the sender, not read from
    /// the quoted message. Passing one of those reports why the quoted
    /// message cannot be opened instead.
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

  /// What about an attachment descriptor is invalid. The descriptors are
  /// checked in order, and each one's fields, a URL card's images
  /// included, in the order they are declared; the first invalid field is
  /// reported.
  public enum AttachmentFailure: Sendable, Hashable {
    /// A media attachment's media hash key is empty.
    case emptyMediaHashKey
    /// A media attachment's width is negative.
    case negativeWidth
    /// A media attachment's height is negative.
    case negativeHeight
    /// A media attachment's file size is not positive.
    case nonPositiveFilesize
    /// A media attachment's filename is empty.
    case emptyFilename
    /// A media attachment's media type is none the protocol defines; the
    /// value is the one passed.
    case unknownMediaType(Int32)
    /// A media attachment's plaintext SHA-256 is given and not empty, and is
    /// not the base64 of 32 bytes. An empty one is taken as not given.
    case plaintextSHA256
    /// A URL attachment's URL is empty.
    case emptyURL
    /// An image of a URL card is invalid: the first value says which, the
    /// second what about it.
    case cardImage(CardImage, CardImageFailure)
    /// A post attachment has neither a rest id nor a post URL.
    case postWithoutReference
  }

  /// Which image of a URL card an error is about.
  public enum CardImage: Sendable, Hashable {
    /// The card's banner image (`bannerImage`).
    case banner
    /// The card's favicon (`faviconImage`).
    case favicon
  }

  /// What about an image of a URL card is invalid. Its width and height
  /// are optional; one that is given must not be negative.
  public enum CardImageFailure: Sendable, Hashable {
    /// The image's media hash key is empty.
    case emptyMediaHashKey
    /// The image's file size is not positive.
    case nonPositiveFilesize
    /// The image's filename is empty.
    case emptyFilename
    /// The image's width is negative.
    case negativeWidth
    /// The image's height is negative.
    case negativeHeight
  }

  /// Which message an error is about: the message whose event was passed,
  /// or the message a reply quotes.
  public enum MessageRole: Sendable, Hashable {
    /// The message whose event was passed to the call. `encryptReply`
    /// never reports it: the event it is given is the message it quotes
    /// (`quotedMessage`), and the reply it builds is not opened.
    case message
    /// The message a reply quotes: the event passed to `encryptReply` as
    /// the one it replies to, or the message a received reply embeds in its
    /// preview.
    case quotedMessage
  }

  /// Which of this device's private keys an error is about.
  public enum KeyPurpose: Sendable, Hashable {
    /// The identity key, which conversation keys are encrypted to.
    case identity
    /// The signing key, which signs the events this device sends.
    case signing
  }
}

// MARK: Invalid state

extension XChatError {
  /// What the chat's state lacks.
  public enum StateFailure: Sendable, Hashable {
    /// No keys are loaded: import keys first. Every call that cannot do
    /// without a loaded key reports this on a core with none: the calls
    /// that return or export the keys, and sends and key changes, though
    /// they need only the signing key.
    case keysNotLoaded
    /// Keys are loaded, but without a signing key: they were imported for
    /// identity-only use, with no `signingPrivateKey`. Sends, key changes
    /// and `getPublicKeys` need one.
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
    /// The contents of the message the role names are malformed Thrift:
    /// the plaintext they decrypted to, or, for an unencrypted message, the
    /// contents as sent. Opening a reply's media reads both the reply and
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

  /// Why base64 does not decode. Padding is optional, and up to two `=`
  /// are accepted whatever the length.
  public enum Base64Failure: Sendable, Hashable {
    /// Data follows `=` padding.
    case dataAfterPadding
    /// A byte is not in the alphabet; the value is that byte.
    case invalidByte(UInt8)
    /// The characters before any `=` number one more than a multiple of
    /// four, which no bytes encode to: the last would carry six bits, less
    /// than a byte. The value is that number.
    case invalidLength(Int)
    /// The input ends in more than two `=`, more than any encoding pads
    /// with; the value is how many. A length that is also invalid is
    /// reported first, as `invalidLength`.
    case excessPadding(Int)
  }

  /// Why hex does not decode.
  public enum HexFailure: Sendable, Hashable {
    /// The input has an odd number of bytes; the value is that number.
    case oddLength(Int)
    /// A byte is not a hex digit; the value is that byte. The rest of the
    /// input is not kept, since it may be a key.
    case invalidByte(UInt8)
  }

  /// Why a Thrift binary-protocol encoding is malformed. Sizes, counts and
  /// limits are `Int`s, whatever width the wire declares them in.
  ///
  /// `field` is the field's name in the Thrift schema, such as
  /// `"message_id"`, for the developer reading the error. It is a `String`
  /// rather than an enum, unlike the other values errors carry: the
  /// schema's structs have dozens of fields, which change with the
  /// protocol, and a field of malformed data is nothing a caller can act
  /// on by case. A caller matches the case, not the field.
  public enum ThriftFailure: Sendable, Hashable {
    /// The input ends inside a value.
    case unexpectedEnd
    /// A type byte names no Thrift type; the value is that byte.
    case unknownType(UInt8)
    /// A binary value or container declares a negative size; the value is
    /// that size.
    case negativeSize(ThriftType, Int)
    /// A binary value or container declares a size over the limit; the
    /// value is that size.
    case sizeExceedsMaximum(ThriftType, Int, maximum: Int)
    /// The containers read so far hold more elements in total than the
    /// limit; the value is that total.
    case totalElementsExceedMaximum(Int, maximum: Int)
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
    /// An encrypted file did not decrypt. `mediaHashKey` is the one the
    /// call that opened the file was given, so the call decides whether it
    /// is set, not where the key came from: `decryptFile`, `fileDecryptor`
    /// and `FileDecryptor(key:mediaHashKey:)` set it, and
    /// `decryptFileWithKey` and `FileDecryptor(key:)`, which take none,
    /// leave it nil.
    case file(FileFailure, mediaHashKey: String?)
    /// A message is encrypted under a conversation-key version there is no
    /// key for. `available` lists the versions there were keys for: those
    /// given and, in `decryptEvents`, those adopted from the batch's key
    /// changes. They are in numeric order (`["9", "10"]`): sorted by
    /// length, then character by character, so a version that is not in
    /// canonical decimal form sorts by its length too.
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
    /// The key is not 32 bytes; the value is its length. The key is one
    /// the contents are opened with as it is: a conversation key given for
    /// opening received messages, for a message encrypted under it
    /// directly, or the per-message key a reply carries for the message it
    /// quotes (`ContentsKey.carriedByReply`). A per-message key derived
    /// from a conversation key is 32 bytes whatever that key's length, and
    /// fails to authenticate instead. The key a sending call sends under is
    /// checked before any message is opened, as
    /// `InputFailure.conversationKeyLength`.
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
    /// two cannot be told apart. Data after a final frame shorter than a
    /// full one can fail this way too (see `dataAfterFinalFrame`).
    case authenticationFailed
    /// The last frame did not authenticate. Bytes cut short inside that
    /// frame fail the same way, so besides being corrupted or another
    /// file's, the bytes may be truncated. Data after a final frame
    /// shorter than a full one can fail this way too (see
    /// `dataAfterFinalFrame`).
    case lastFrameAuthenticationFailed
    /// Data follows the file's final frame, and that frame is a full one
    /// (1041 bytes, from a file whose plaintext fills its last 1024-byte
    /// chunk).
    ///
    /// Frames are read 1041 bytes at a time, and only a frame that
    /// authenticates says it is the final one, so data after a shorter
    /// final frame, or after the header of an empty file, is read as part
    /// of a frame, which then does not authenticate. When the frame read
    /// is the last, that is `lastFrameAuthenticationFailed`; when more
    /// bytes follow it, `authenticationFailed`.
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
    /// An event's signature could not be checked, and unverified events are
    /// rejected. The event is an unencrypted message, which is never
    /// verified, whether or not it carries a signature; or it carries no
    /// signature; or no signing key of its sender was given at the key
    /// version its signature names; or the payload the signature covers
    /// cannot be rebuilt from the event: the event lacks a field the payload
    /// signs (its message id or sender id; for a key change, also its
    /// conversation-key version, or has one that is not an integer, which
    /// the payload signs as an integer; and before signature version 6 its
    /// participants' keys, or from version 6 on the plaintext conversation
    /// key, which this device could not decrypt and no key was given for),
    /// or a field contains a comma, which the comma-joined payload cannot
    /// hold unambiguously.
    ///
    /// A signing key given with an identity-key binding (any of
    /// `SigningKeyEntry`'s `identityPublicKey`, `identityPublicKeySignature`
    /// and `signingPublicKeySignature` set) is used only when the binding
    /// verifies: `signingPublicKeySignature` is the identity key's signature
    /// over the signing key. A key whose binding does not verify (the
    /// signature does not match, `identityPublicKey` or
    /// `signingPublicKeySignature` is missing, or a key or the signature
    /// does not decode) is not used, so when it is the sender's only key at
    /// the event's key version, the event is unverifiable as if no key had
    /// been given. Such a binding may mean the key is not the sender's.
    case unverifiable(SignedEvent)
    /// An event's signature was checked and does not hold.
    case rejected(SignedEvent, SignatureFailure)
  }

  /// The kind of event whose signature an error is about.
  public enum SignedEvent: Sendable, Hashable {
    /// A message event: a text message, reaction, edit, or another entry a
    /// conversation's messages carry.
    case message
    /// A conversation-key change, which hands each participant the new
    /// conversation key.
    case keyChange
  }

  /// Why an event's signature was rejected.
  ///
  /// The signature's version is checked first, then the signing key at the
  /// event's key version, then the signature's bytes against it. A key that
  /// is not a P-256 public key is `invalidSigningPublicKey` even when the
  /// signature's bytes are malformed too: the key is the caller's, and no
  /// event signed at its version can verify until it is replaced. An event
  /// with no signature is `VerificationFailure.unverifiable` before its
  /// version is checked, and one with no signing key at its key version, or
  /// whose signed payload cannot be rebuilt, before its key is.
  ///
  /// Only a key given without an identity-key binding (none of
  /// `SigningKeyEntry`'s `identityPublicKey`, `identityPublicKeySignature`
  /// and `signingPublicKeySignature` set) reaches this check as it is. A
  /// key given with a binding is checked when the binding is, before any
  /// event: one that is not a P-256 public key fails its binding and is
  /// not used, so an event only it could verify is
  /// `VerificationFailure.unverifiable`, not `invalidSigningPublicKey`.
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
    /// The signing key at `keyVersion`, the event's key version, is not a
    /// P-256 public key. It was given without an identity-key binding: one
    /// given with a binding that is not a P-256 public key is not used, as
    /// the enum's documentation says.
    case invalidSigningPublicKey(keyVersion: String)
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
