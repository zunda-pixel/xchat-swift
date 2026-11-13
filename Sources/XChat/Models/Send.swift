/// The wire format messages are sent in.
public enum SendVersion: Sendable, Equatable {
  /// Contents under the conversation key, signed at version 7: the
  /// older format every client reads.
  case v0
  /// Contents under a key derived per message (from the conversation key,
  /// sender, and message id), with `contents_encryption_version` 1 and
  /// signatures at version 10 that cover it. Files use per-attachment keys.
  case v1
}

/// A span of the text marked as a hashtag, mention, link, and so on.
/// Offsets count UTF-8 bytes, `start` inclusive and `end` exclusive.
public struct EntityDescriptor: Sendable, Equatable {
  public var start: Int32
  public var end: Int32
  public var type: EntityKind

  public init(start: Int32, end: Int32, type: EntityKind) {
    self.start = start
    self.end = end
    self.type = type
  }
}

/// An encrypted preview image referenced by a URL card attachment.
public struct UrlAttachmentImageDescriptor: Sendable, Equatable {
  public var mediaHashKey: String
  /// Size of the encrypted image in bytes (`encryptedFileSize` of it).
  public var filesizeBytes: Int64
  public var filename: String
  public var width: Int64?
  public var height: Int64?

  public init(
    mediaHashKey: String,
    filesizeBytes: Int64,
    filename: String,
    width: Int64? = nil,
    height: Int64? = nil
  ) {
    self.mediaHashKey = mediaHashKey
    self.filesizeBytes = filesizeBytes
    self.filename = filename
    self.width = width
    self.height = height
  }
}

/// One attachment an outgoing message carries.
public enum AttachmentDescriptor: Sendable, Equatable {
  /// A media attachment: an encrypted file the message references by its
  /// media hash key. `filesizeBytes` is the encrypted size
  /// (`encryptedFileSize`), which must be positive.
  case media(
    mediaHashKey: String,
    width: Int64,
    height: Int64,
    filesizeBytes: Int64,
    filename: String,
    mediaType: Int32?,
    durationMilliseconds: Int64?,
    plaintextSHA256: String?)
  /// A URL card, optionally with its encrypted banner and favicon images.
  case url(
    url: String,
    displayTitle: String?,
    bannerImage: UrlAttachmentImageDescriptor?,
    faviconImage: UrlAttachmentImageDescriptor?)
  /// A post attachment, named by its `rest_id`, its `post_url`, or both.
  case post(restId: String?, postURL: String?)
}

/// What the API needs to send a message.
public struct EncryptedMessagePayload: Sendable, Equatable {
  /// The id the SDK minted and embedded in the signed event. Send it as
  /// the message's `message_id`, and reuse the same payload on retries.
  public var messageId: String
  /// The outgoing message as base64: what recipients receive.
  public var eventB64: String
  /// Base64 Thrift `MessageCreateEvent`: the send request's
  /// `encoded_message_create_event`.
  public var encodedMessageCreateEvent: String
  /// Base64 ECDSA signature (unpadded).
  public var signature: String
  /// Base64 Thrift `MessageEventSignature`: the send request's
  /// `encoded_message_event_signature`.
  public var encodedMessageEventSignature: String
  public var conversationKeyVersion: String
  public var shouldNotify: Bool
}

/// A signed action (such as a key change), shaped as requests carry it.
public struct ActionSignatureInfo: Sendable, Equatable {
  public var messageId: String
  /// Base64 Thrift `MessageEventDetail`.
  public var encodedMessageEventDetail: String
  public var signature: MessageEventSignatureSummary
}

public struct MessageEventSignatureSummary: Sendable, Equatable {
  public var signature: String
  public var publicKeyVersion: String
  public var signatureVersion: String
  /// The signer's base64 signing public key: set on action signatures,
  /// absent on message sends.
  public var signingPublicKey: String?
}

/// A prepared conversation-key change: a fresh key, each participant's
/// encrypted copy of it, and the signed event to send.
public struct PreparedConversationChange: Sendable, Equatable {
  public var conversationId: String
  /// The raw key to store locally and encrypt this conversation's
  /// messages with.
  public var conversationKey: [UInt8]
  public var conversationKeyVersion: String
  public var participantKeys: [ParticipantKey]
  public var actionSignature: ActionSignatureInfo
}

/// A participant's identity key, as the X API returns it.
public struct ConversationParticipantPublicKey: Sendable, Equatable {
  public var userId: String
  /// Base64 identity public key (SEC1 or SPKI).
  public var identityPublicKey: String
  public var publicKeyVersion: String

  public init(userId: String, identityPublicKey: String, publicKeyVersion: String) {
    self.userId = userId
    self.identityPublicKey = identityPublicKey
    self.publicKeyVersion = publicKeyVersion
  }
}
