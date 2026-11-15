public import Foundation

/// English descriptions for logs, built from each case and its values. The
/// cases, not these strings, are what callers match on.

extension XChatError: LocalizedError, CustomStringConvertible {
  public var errorDescription: String? { description }

  public var description: String {
    switch self {
    case .invalidInput(let failure): failure.description
    case .invalidState(let failure): failure.description
    case .parse(let failure): failure.description
    case .decryption(let failure): failure.description
    case .verification(let failure): failure.description
    case .internalError(let failure): failure.description
    }
  }
}

extension XChatError.InputFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .conversationKeyLength(let length):
      "Conversation key must be 32 bytes, got \(length)"
    case .fileKeyLength(let length):
      "Invalid key (expected 32 bytes, got \(length))"
    case .privateKey:
      "Invalid private key: not a P-256 scalar"
    case .signingKeyVersionNotSet:
      "signing key version is not set: import keys with its public key version"
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
      "the identity public key of participant \(userId) is not the base64 of a P-256 public "
        + "key in SEC1 or SPKI DER"
    case .noParticipants:
      "public_keys must not be empty"
    case .conversationIdNotDerivable(let distinctUsers):
      "cannot derive a one-to-one conversation id from \(distinctUsers) distinct user(s); "
        + "pass conversation_id explicitly for group conversations"
    case .signaturePayloadContainsComma:
      "Signature payload contains comma-separated component"
    case .entityRange(let start, let end):
      "Invalid entity: offsets \(start)..<\(end) are not a range of the text"
    case .attachment(let index, let failure):
      "Invalid attachments[\(index)]: \(failure)"
    case .emptyTargetSequenceId:
      "Invalid target message sequence id: must not be empty"
    case .emptyReactionEmoji:
      "Invalid reaction emoji: must not be empty"
    case .notMessageEvent(.message):
      "the event is not a message: pass the event of a message"
    case .notMessageEvent(.quotedMessage):
      "the quoted event is not a message: pass the event of a message"
    case .messageIsEdit(let role):
      "\(role) is an edit: pass the event of the message that was edited"
    case .notTextMessage(let role):
      "\(role) is a reaction, read marker, or other entry, not a text message"
    case .notEncrypted(let role):
      "\(role) is not encrypted, so neither is its media: use the downloaded bytes as "
        + "they are"
    case .noContents(let role):
      "\(role) has no contents"
    case .noSequenceId(let role):
      "\(role) carries no sequence_id"
    case .carriedMessageKeyLength(let length):
      "the key the reply carries for the quoted message is \(length) bytes, not 32: "
        + "pass the quoted message's own event"
    case .quotedMessageNotEmbedded:
      "the reply does not embed the message it quotes, so that message can't be opened "
        + "through the reply: pass the quoted message's own event"
    case .quotedMessageInOtherConversation:
      "the quoted message belongs to a different conversation than the reply"
    case .emptyMediaHashKey:
      "media_hash_key is empty: pass the media hash key of the attachment, as the "
        + "message lists it"
    case .mediaHashKeyNotFound(_, let available) where available.isEmpty:
      "the message has no media: pass the event of the message that carries the media"
    case .mediaHashKeyNotFound(let mediaHashKey, let available):
      "media_hash_key '\(mediaHashKey)' is not in the message, whose media hash keys are "
        + "\(available.joined(separator: ", ")): pass one of those, or the event of the "
        + "message that carries this media"
    case .quotedMediaHashKey(let mediaHashKey):
      "media_hash_key '\(mediaHashKey)' is media the reply quotes: its file belongs to "
        + "the quoted message and was uploaded with it, so there is nothing to encrypt"
    case .fileEncryptorFinished:
      "File encryptor already finished"
    case .fileDecryptorFinished:
      "File decryptor already finished"
    }
  }
}

extension XChatError.AttachmentFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .emptyMediaHashKey: "media_hash_key must not be empty"
    case .negativeDimensions: "width and height must not be negative"
    case .nonPositiveFilesize: "filesize_bytes must be positive"
    case .emptyFilename: "filename must not be empty"
    case .unknownMediaType(let mediaType): "media_type \(mediaType) is not a media type"
    case .plaintextSHA256:
      "plaintext_sha256 must be the base64 SHA-256 of the file's plaintext bytes"
    case .emptyURL: "url must not be empty"
    case .postWithoutReference: "a post needs rest_id, post_url, or both"
    case .imageEmptyMediaHashKey: "image media_hash_key must not be empty"
    case .imageNonPositiveFilesize: "image filesize_bytes must be positive"
    case .imageEmptyFilename: "image filename must not be empty"
    case .imageNegativeWidth: "image width must not be negative"
    case .imageNegativeHeight: "image height must not be negative"
    }
  }
}

extension XChatError.MessageRole: CustomStringConvertible {
  public var description: String {
    switch self {
    case .message: "the message"
    case .quotedMessage: "the quoted message"
    }
  }
}

extension XChatError.StateFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .keysNotLoaded: "keys are not loaded: import keys first"
    case .signingKeyNotLoaded: "signing key is not loaded"
    }
  }
}

extension XChatError.ParseFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .base64(let failure): failure.description
    case .hex(let failure): failure.description
    case .event(.base64(let failure)): "Invalid base64 event: \(failure)"
    case .event(.thrift(let failure)): "Thrift parse error: \(failure)"
    case .messageContents(let failure): "Content parse error: \(failure)"
    }
  }
}

extension XChatError.Base64Failure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .dataAfterPadding: "Invalid base64: '=' is followed by data"
    case .invalidCharacter(let byte): "Invalid base64 character: \(Unicode.Scalar(byte))"
    case .invalidLength(let length): "Invalid base64 length: \(length)"
    }
  }
}

extension XChatError.HexFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .oddLength(let length): "Invalid hex length: \(length)"
    case .invalidCharacter(let byte): "Invalid hex character: \(Unicode.Scalar(byte))"
    }
  }
}

extension XChatError.ThriftFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .unexpectedEnd:
      "Thrift input ended unexpectedly"
    case .unknownType(let wire):
      "Thrift input has an unknown type: \(wire)"
    case .negativeSize(let type, let size):
      "Thrift \(type) has a negative size: \(size)"
    case .sizeExceedsMaximum(let type, let size, let maximum):
      "Thrift \(type) size \(size) exceeds maximum \(maximum)"
    case .totalElementsExceedMaximum(let total, let maximum):
      "Thrift cumulative container elements \(total) exceed maximum \(maximum)"
    case .nestingTooDeep(let maximum):
      "Thrift nesting exceeds maximum depth \(maximum)"
    case .invalidUTF8:
      "Thrift input has invalid UTF-8"
    case .fieldType(let field, let id, let actual, let expected):
      "Thrift field \(field) (#\(id)) is \(actual), expected \(expected)"
    case .listElementType(let field, let actual, let expected):
      "Thrift list \(field) has element type \(actual), expected \(expected)"
    case .mapTypes(let field, let key, let value):
      "Thrift map \(field) is \(key) to \(value), expected string to string"
    case .messageAttachmentWithoutVariant:
      "message attachment carries no variant"
    case .previewAttachmentWithoutVariant:
      "preview attachment carries no variant"
    }
  }
}

extension XChatError.DecryptionFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .messageContents(let role, let failure, let key):
      Self.describe(failure, of: role, under: key)
    case .file(let fault, let mediaHashKey?):
      Self.describe(fault, mediaHashKey: mediaHashKey)
    case .file(let fault, nil):
      Self.describe(fault)
    case .missingConversationKey(let role, let version, let available) where available.isEmpty:
      "\(role) is encrypted under conversation-key version '\(version)', and no "
        + "conversation keys were given"
    case .missingConversationKey(let role, let version, let available):
      "\(role) is encrypted under conversation-key version '\(version)', and no key was "
        + "given for it; keys were given for versions \(available.joined(separator: ", "))"
    case .missingSenderOrMessageId(let role):
      "\(role) uses per-message keys, which derive from its event's sender id and message "
        + "id, and the event lacks one of them"
    case .nonNumericSenderId(let role, let senderId):
      "\(role) uses a per-message key, which derives from its sender id in decimal digits, "
        + "and its event's sender id is '\(senderId)'"
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
      "the contents of \(role) do not decrypt under \(source): it is not the key they "
        + "were encrypted under, or they are corrupted"
    case .ciphertextTooShort:
      "the contents of \(role) are too short to be encrypted contents"
    case .keyLength(let length):
      "\(source) is \(length) bytes, not 32, so it cannot decrypt the contents of \(role)"
    }
  }

  private static func describe(_ fault: XChatError.FileFailure) -> String {
    switch fault {
    case .authenticationFailed:
      "the bytes are not a file encrypted under this key, or they are corrupted: pass "
        + "the encrypted bytes and the key they were encrypted under"
    case .lastFrameAuthenticationFailed:
      "the bytes are not the complete file encrypted under this key: they are "
        + "truncated, corrupted, or another file"
    case .dataAfterFinalFrame:
      "the bytes continue past the end of the encrypted file: pass only its bytes"
    case .truncated:
      "the encrypted file is truncated: pass all of its bytes"
    case .unknownTag(let tag):
      "a frame of the encrypted file authenticated but carries tag \(tag), which the file "
        + "format does not define"
    }
  }

  private static func describe(_ fault: XChatError.FileFailure, mediaHashKey: String) -> String {
    switch fault {
    case .authenticationFailed:
      "the bytes are not the encrypted file of media_hash_key '\(mediaHashKey)', or they "
        + "are corrupted: pass the bytes downloaded for that media hash key"
    case .lastFrameAuthenticationFailed:
      "the bytes are not the complete encrypted file of media_hash_key '\(mediaHashKey)': "
        + "they are truncated, corrupted, or another file; pass the complete bytes "
        + "downloaded for that media hash key"
    case .dataAfterFinalFrame:
      "the bytes continue past the end of the encrypted file of media_hash_key "
        + "'\(mediaHashKey)': pass only the bytes downloaded for that media hash key"
    case .truncated:
      "the bytes of media_hash_key '\(mediaHashKey)' are truncated: pass the complete "
        + "bytes downloaded for that media hash key"
    case .unknownTag(let tag):
      "a frame of the encrypted file of media_hash_key '\(mediaHashKey)' authenticated but "
        + "carries tag \(tag), which the file format does not define"
    }
  }
}

extension XChatError.FileFailure: CustomStringConvertible {
  public var description: String {
    XChatError.DecryptionFailure.file(self, mediaHashKey: nil).description
  }
}

extension XChatError.VerificationFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .unverifiable(let event):
      "\(event) signature could not be verified: signature missing or no matching "
        + "signing key"
    case .rejected(let event, let rejection):
      "\(event) signature verification failed: \(rejection)"
    }
  }
}

extension XChatError.SignedEvent: CustomStringConvertible {
  public var description: String {
    switch self {
    case .message: "Message"
    case .keyChange: "KeyChange"
    }
  }
}

extension XChatError.SignatureFailure: CustomStringConvertible {
  public var description: String {
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

extension XChatError.InternalFailure: CustomStringConvertible {
  public var description: String {
    switch self {
    case .sodiumInitializationFailed:
      "libsodium initialization failed"
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
      "an error that is not an XChatError was raised inside the SDK: \(description)"
    }
  }
}
