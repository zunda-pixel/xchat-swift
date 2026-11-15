public import Foundation

/// English descriptions for developers and logs, built from each case and
/// its values. They are not localized and not meant for users: the cases,
/// not these strings, are what callers match on, and an app shows its own
/// text for the cases it handles.
///
/// Every description is a sentence that starts with a capital letter. What
/// a nested failure adds after a colon (an attachment's fault, a base64,
/// hex or Thrift failure, a signature failure) is a fragment that starts
/// as it would mid-sentence, often with a field name as the other bindings
/// write it. The case that holds it names what was read or checked, and
/// the fragment does not repeat that ("Invalid base64 event: byte '!'
/// (0x21) is not in the alphabet"). A count takes the singular for one
/// ("1 character").
///
/// Only `XChatError` describes itself in English. Its nested enums print as
/// Swift writes their cases, and its debug description is the expression
/// that builds it, so a value in a log or the debugger shows the case to
/// match.

extension XChatError: LocalizedError, CustomStringConvertible, CustomDebugStringConvertible {
  /// The same English text as `description`, for developers and logs. It is
  /// neither localized nor meant for users: match the case and show text of
  /// your own. `LocalizedError` is adopted so that `localizedDescription`
  /// describes the case when the error is held as `any Error`, where
  /// Foundation would otherwise give generic text, not to make this text
  /// fit for display.
  public var errorDescription: String? { description }

  /// The case and its values in English, for developers and logs; see
  /// `errorDescription`.
  public var description: String {
    switch self {
    case .invalidInput(let failure): failure.explanation
    case .invalidState(let failure): failure.explanation
    case .parse(let failure): failure.explanation
    case .decryption(let failure): failure.explanation
    case .verification(let failure): failure.explanation
    case .internalError(let failure): failure.explanation
    }
  }

  /// The error as the Swift expression that builds it, with every nested
  /// case written `.name(values)`, such as
  /// `XChatError.invalidInput(.attachment(index: 2, .emptyFilename))`, so
  /// debugging shows the pattern to match at any depth.
  public var debugDescription: String {
    "XChatError" + caseExpression(self)
  }
}

/// `value` as Swift writes it where its type is implied: an enum case as
/// `.name` or `.name(values)`, an optional as its value or `nil`, an array
/// in brackets, and anything else as `String(reflecting:)` writes it (a
/// string quoted, a number in digits).
///
/// It reads the cases through `Mirror` rather than a switch per nested
/// enum, which every added case would have to extend. A case without
/// values has no payload to reflect, so its name is its description: the
/// nested enums do not describe themselves, so Swift prints the case name.
private func caseExpression(_ value: Any) -> String {
  let mirror = Mirror(reflecting: value)
  switch mirror.displayStyle {
  case .enum:
    guard let payload = mirror.children.first, let name = payload.label else {
      return ".\(value)"
    }
    return ".\(name)(\(caseArguments(payload.value)))"
  case .optional:
    return mirror.children.first.map { caseExpression($0.value) } ?? "nil"
  case .collection:
    return "[" + mirror.children.map { caseExpression($0.value) }.joined(separator: ", ") + "]"
  default:
    return String(reflecting: value)
  }
}

/// A case's values. A payload of several values, or of one labeled value,
/// reflects as a tuple whose unlabeled elements `Mirror` names `.0`, `.1`,
/// and so on; those are written without a label.
private func caseArguments(_ payload: Any) -> String {
  let mirror = Mirror(reflecting: payload)
  guard mirror.displayStyle == .tuple else { return caseExpression(payload) }
  return mirror.children.map { element in
    let value = caseExpression(element.value)
    guard let label = element.label, !label.hasPrefix(".") else { return value }
    return "\(label): \(value)"
  }
  .joined(separator: ", ")
}

extension XChatError.InputFailure {
  var explanation: String {
    switch self {
    case .conversationKeyLength(let length):
      "Conversation key must be 32 bytes, got \(length)"
    case .fileKeyLength(let length):
      "File key must be 32 bytes, got \(length)"
    case .privateKey(let purpose):
      "Invalid \(purpose.name) private key: not a P-256 scalar"
    case .publicKeyVersion(let version):
      "Invalid public key version '\(version)': pass the key version as the X API "
        + "returns it, an integer in digits"
    case .senderId(let value):
      "Invalid sender_id '\(value)': pass a numeric user id (digits only)"
    case .conversationKeyVersion(let value):
      "Invalid conversation_key_version '\(value)': pass the key version as the X API "
        + "returns it, an integer in digits"
    case .participantUserId(let value):
      "Invalid public_keys user_id '\(value)': pass a numeric user id (digits only)"
    case .participantKeyVersion(let value):
      "Invalid public_keys public_key_version '\(value)': pass the key version as the X "
        + "API returns it, an integer in digits"
    case .participantIdentityKey(let userId):
      "The identity public key of participant \(userId) is not the base64 of a P-256 public "
        + "key in SEC1 or SPKI DER"
    case .noParticipants:
      "Invalid public_keys: must not be empty"
    case .conversationIdNotDerivable(let distinctUsers):
      "Cannot derive a one-to-one conversation id from "
        + "\(counted(distinctUsers, "distinct user")); pass conversation_id explicitly for "
        + "group conversations"
    case .signaturePayloadContainsComma:
      "Signature payload contains comma-separated component"
    case .entityRange(let start, let end):
      "Invalid entity: offsets \(start)..<\(end) are not a range of the text"
    case .attachment(let index, let failure):
      "Invalid attachments[\(index)]: \(failure.explanation)"
    case .emptyTargetSequenceId:
      "Invalid target message sequence id: must not be empty"
    case .emptyReactionEmoji:
      "Invalid reaction emoji: must not be empty"
    case .notMessageEvent(.message):
      "The event is not a message: pass the event of a message"
    case .notMessageEvent(.quotedMessage):
      "The quoted event is not a message: pass the event of a message"
    case .messageIsEdit(let role):
      "\(role.subject) is an edit, which carries neither the edited message's text nor its "
        + "media"
    case .notTextMessage(let role):
      "\(role.subject) is a reaction, read marker, or other entry, not a text message"
    case .notEncrypted(let role):
      "\(role.subject) is not encrypted, so neither is its media"
    case .noContents(let role):
      "\(role.subject) has no contents"
    case .noSequenceId(let role):
      "\(role.subject) carries no sequence_id"
    case .quotedMessageNotEmbedded:
      "The reply does not embed the message it quotes, so that message can't be opened "
        + "through the reply: pass the quoted message's own event"
    case .quotedMessageInOtherConversation:
      "The quoted message belongs to a different conversation than the reply"
    case .emptyMediaHashKey:
      "Empty media_hash_key: pass the media hash key of the attachment, as the message "
        + "lists it"
    case .mediaHashKeyNotFound(let mediaHashKey, let available) where available.isEmpty:
      "The media_hash_key '\(mediaHashKey)' is not among the media hash keys this call can "
        + "use: "
        + "there are none"
    case .mediaHashKeyNotFound(let mediaHashKey, let available):
      "The media_hash_key '\(mediaHashKey)' is not among the media hash keys this call can "
        + "use: "
        + available.joined(separator: ", ")
    case .quotedMediaHashKey(let mediaHashKey):
      "The media_hash_key '\(mediaHashKey)' is media the reply quotes: its file belongs to "
        + "the quoted message and was uploaded with it, so there is nothing to encrypt"
    case .fileEncryptorFinished:
      "File encryptor already finished"
    case .fileDecryptorFinished:
      "File decryptor already finished"
    }
  }
}

extension XChatError.AttachmentFailure {
  var explanation: String {
    switch self {
    case .emptyMediaHashKey: "media_hash_key must not be empty"
    case .negativeWidth: "width must not be negative"
    case .negativeHeight: "height must not be negative"
    case .nonPositiveFilesize: "filesize_bytes must be positive"
    case .emptyFilename: "filename must not be empty"
    case .unknownMediaType(let mediaType): "media_type \(mediaType) is not a media type"
    case .plaintextSHA256:
      "plaintext_sha256 must be the base64 SHA-256 of the file's plaintext bytes"
    case .emptyURL: "url must not be empty"
    case .cardImage(let image, let failure): "\(image.field).\(failure.explanation)"
    case .postWithoutReference: "a post needs rest_id, post_url, or both"
    }
  }
}

extension XChatError.CardImageFailure {
  var explanation: String {
    switch self {
    case .emptyMediaHashKey: "media_hash_key must not be empty"
    case .nonPositiveFilesize: "filesize_bytes must be positive"
    case .emptyFilename: "filename must not be empty"
    case .negativeWidth: "width must not be negative"
    case .negativeHeight: "height must not be negative"
    }
  }
}

extension XChatError.CardImage {
  /// The image's field in a URL attachment, as the other bindings name it.
  var field: String {
    switch self {
    case .banner: "banner_image"
    case .favicon: "favicon_image"
    }
  }
}

extension XChatError.MessageRole {
  /// The message as a sentence names it.
  var noun: String {
    switch self {
    case .message: "the message"
    case .quotedMessage: "the quoted message"
    }
  }

  /// The message as a sentence that starts with it names it.
  var subject: String {
    switch self {
    case .message: "The message"
    case .quotedMessage: "The quoted message"
    }
  }
}

extension XChatError.KeyPurpose {
  /// The key as a sentence names it, before "private key".
  var name: String {
    switch self {
    case .identity: "identity"
    case .signing: "signing"
    }
  }
}

extension XChatError.StateFailure {
  var explanation: String {
    switch self {
    case .keysNotLoaded: "Keys are not loaded: import keys first"
    case .signingKeyNotLoaded: "Signing key is not loaded"
    case .signingKeyVersionNotSet:
      "Signing key version is not set: import keys with their public key version, or set "
        + "it with setPublicKeyVersion"
    }
  }
}

extension XChatError.ParseFailure {
  var explanation: String {
    switch self {
    case .base64(let failure): "Invalid base64: \(failure.explanation)"
    case .hex(let failure): "Invalid hex: \(failure.explanation)"
    case .event(.base64(let failure)): "Invalid base64 event: \(failure.explanation)"
    case .event(.thrift(let failure)): "Thrift parse error: \(failure.explanation)"
    case .messageContents(let role, let failure):
      "Content parse error in \(role.noun): \(failure.explanation)"
    }
  }
}

extension XChatError.Base64Failure {
  var explanation: String {
    switch self {
    case .dataAfterPadding: "'=' is followed by data"
    case .invalidByte(let byte): "byte \(describeByte(byte)) is not in the alphabet"
    case .invalidLength(let length):
      "\(counted(length, "character")) before any '=', a length no bytes encode to"
    case .excessPadding(let count): "\(count) '=' of padding, where at most 2 are accepted"
    }
  }
}

extension XChatError.HexFailure {
  var explanation: String {
    switch self {
    case .oddLength(let length): "\(counted(length, "byte")), an odd number"
    case .invalidByte(let byte): "byte \(describeByte(byte)) is not a hex digit"
    }
  }
}

/// `count` and `noun`, in the plural unless the count is one: `1 byte`,
/// `0 bytes`, `31 bytes`. Every noun passed takes an `s`.
private func counted(_ count: Int, _ noun: String) -> String {
  "\(count) \(noun)\(count == 1 ? "" : "s")"
}

/// A byte of a string's UTF-8 as hex, after its character when that is
/// printable ASCII: `'!' (0x21)`, `0x0A`, `0xC3`. Not the character alone:
/// a byte from 0x80 up is part of a multi-byte character, so read as a
/// scalar it is another character, and a control character would be
/// written into the text as is.
private func describeByte(_ byte: UInt8) -> String {
  guard (0x20...0x7E).contains(byte) else { return hex(byte) }
  return "'\(Character(Unicode.Scalar(byte)))' (\(hex(byte)))"
}

/// A byte as two hex digits after `0x`: `0x05`, `0x9E`. A Thrift type
/// byte is written this way alone, without the character
/// `describeByte` adds: it is not part of a string.
private func hex(_ byte: UInt8) -> String {
  "0x" + (byte < 0x10 ? "0" : "") + String(byte, radix: 16, uppercase: true)
}

extension XChatError.ThriftFailure {
  var explanation: String {
    switch self {
    case .unexpectedEnd:
      "input ended unexpectedly"
    case .unknownType(let wire):
      "unknown type byte \(hex(wire))"
    case .negativeSize(let type, let size):
      "\(type) has a negative size: \(size)"
    case .sizeExceedsMaximum(let type, let size, let maximum):
      "\(type) size \(size) exceeds maximum \(maximum)"
    case .totalElementsExceedMaximum(let total, let maximum):
      "cumulative container elements \(total) exceed maximum \(maximum)"
    case .nestingTooDeep(let maximum):
      "nesting exceeds maximum depth \(maximum)"
    case .invalidUTF8:
      "input has invalid UTF-8"
    case .fieldType(let field, let id, let actual, let expected):
      "field \(field) (#\(id)) is \(actual), expected \(expected)"
    case .listElementType(let field, let actual, let expected):
      "list \(field) has element type \(actual), expected \(expected)"
    case .mapTypes(let field, let key, let value):
      "map \(field) is \(key) to \(value), expected string to string"
    case .messageAttachmentWithoutVariant:
      "message attachment carries no variant"
    case .previewAttachmentWithoutVariant:
      "preview attachment carries no variant"
    }
  }
}

extension XChatError.DecryptionFailure {
  var explanation: String {
    switch self {
    case .messageContents(let role, let failure, let key):
      Self.describe(failure, of: role, under: key)
    case .file(let fault, let mediaHashKey?):
      Self.describe(fault, mediaHashKey: mediaHashKey)
    case .file(let fault, nil):
      Self.describe(fault)
    case .missingConversationKey(let role, let version, let available) where available.isEmpty:
      "\(role.subject) is encrypted under conversation-key version '\(version)', and there "
        + "were no conversation keys"
    case .missingConversationKey(let role, let version, let available) where available.count == 1:
      "\(role.subject) is encrypted under conversation-key version '\(version)', and there "
        + "was no key for it; there was a key for version \(available[0])"
    case .missingConversationKey(let role, let version, let available):
      "\(role.subject) is encrypted under conversation-key version '\(version)', and there "
        + "was no key for it; there were keys for versions "
        + available.joined(separator: ", ")
    case .missingSenderOrMessageId(let role):
      "\(role.subject) uses per-message keys, which derive from its event's sender id and "
        + "message id, and the event lacks one of them"
    case .nonNumericSenderId(let role, let senderId):
      "\(role.subject) uses a per-message key, which derives from its sender id as a 64-bit "
        + "integer, and its event's sender id '\(senderId)' is not one"
    }
  }

  private static func describe(
    _ failure: XChatError.ContentsFailure,
    of role: XChatError.MessageRole,
    under key: XChatError.ContentsKey
  ) -> String {
    let source =
      switch key {
      case .conversationKey(let version):
        "the conversation key for version '\(version)'"
      case .carriedByReply(let version):
        "the key the reply carries for it (no conversation key was given for version "
          + "'\(version)')"
      }
    return switch failure {
    case .authenticationFailed:
      "The contents of \(role.noun) do not decrypt under \(source): it is not the key they "
        + "were encrypted under, or they are corrupted"
    case .ciphertextTooShort:
      "The contents of \(role.noun) are too short to be encrypted contents"
    case .keyLength(let length):
      "The contents of \(role.noun) cannot be decrypted under \(source): it is "
        + "\(counted(length, "byte")), not 32"
    }
  }

  private static func describe(_ fault: XChatError.FileFailure) -> String {
    switch fault {
    case .authenticationFailed:
      "The bytes are not a file encrypted under this key, or they are corrupted: pass "
        + "the encrypted bytes and the key they were encrypted under"
    case .lastFrameAuthenticationFailed:
      "The bytes are not the complete file encrypted under this key: they are "
        + "truncated, corrupted, or another file"
    case .dataAfterFinalFrame:
      "The bytes continue past the end of the encrypted file: pass only its bytes"
    case .truncated:
      "The encrypted file is truncated: pass all of its bytes"
    case .unknownTag(let tag):
      "A frame of the encrypted file authenticated but carries tag \(tag), which "
        + "secretstream does not define"
    }
  }

  private static func describe(_ fault: XChatError.FileFailure, mediaHashKey: String) -> String {
    switch fault {
    case .authenticationFailed:
      "The bytes are not the encrypted file of media_hash_key '\(mediaHashKey)', or they "
        + "are corrupted: pass the bytes downloaded for that media hash key"
    case .lastFrameAuthenticationFailed:
      "The bytes are not the complete encrypted file of media_hash_key '\(mediaHashKey)': "
        + "they are truncated, corrupted, or another file; pass the complete bytes "
        + "downloaded for that media hash key"
    case .dataAfterFinalFrame:
      "The bytes continue past the end of the encrypted file of media_hash_key "
        + "'\(mediaHashKey)': pass only the bytes downloaded for that media hash key"
    case .truncated:
      "The bytes of media_hash_key '\(mediaHashKey)' are truncated: pass the complete "
        + "bytes downloaded for that media hash key"
    case .unknownTag(let tag):
      "A frame of the encrypted file of media_hash_key '\(mediaHashKey)' authenticated but "
        + "carries tag \(tag), which secretstream does not define"
    }
  }
}

extension XChatError.VerificationFailure {
  var explanation: String {
    switch self {
    case .unverifiable(let event):
      "\(event.name) signature could not be verified: "
        + (event == .message
          ? "the message is not encrypted (an unencrypted message is never verified), " : "")
        + "the event carries no signature, no signing key of its sender was given at its key "
        + "version (a key given with an identity-key binding that does not verify is not "
        + "used), or the signed payload cannot be rebuilt from the event"
    case .rejected(let event, let failure):
      "\(event.name) signature verification failed: \(failure.explanation)"
    }
  }
}

extension XChatError.SignedEvent {
  /// The event type as the protocol names it.
  var name: String {
    switch self {
    case .message: "Message"
    case .keyChange: "KeyChange"
    }
  }
}

extension XChatError.SignatureFailure {
  var explanation: String {
    switch self {
    case .missingSignatureVersion:
      "signature_version is missing or not an integer"
    case .signatureVersionTooOld(let version, let minimum):
      "signature_version \(version) is no longer accepted (minimum: \(minimum))"
    case .signatureVersionUnsupported(let version, let maximum):
      "signature_version \(version) is not supported (maximum: \(maximum))"
    case .mismatch(let keyVersion):
      "ECDSA mismatch: key_version=\(keyVersion)"
    case .malformedSignature:
      "the signature is not a 64-byte ECDSA P-256 signature"
    case .invalidSigningPublicKey:
      "the signing key is not a P-256 public key"
    }
  }
}

extension XChatError.InternalFailure {
  var explanation: String {
    switch self {
    case .sodiumInitializationFailed:
      "Initializing libsodium failed"
    case .streamInitializationFailed:
      "Secretstream initialization failed"
    case .streamEncryptionFailed:
      "Secretstream encryption failed"
    case .secretboxEncryptionFailed:
      "Secretbox encryption failed"
    case .keyAgreementFailed:
      "P-256 key agreement failed"
    case .gcmEncryptionFailed:
      "AES-GCM encryption failed"
    case .signingFailed:
      "ECDSA signing failed"
    case .unexpected(let description):
      "An error that is not an XChatError was raised inside the SDK: \(description)"
    }
  }
}
