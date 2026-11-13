/// Who sent an event, and where it sits in the conversation.
public struct EventMeta: Sendable, Equatable {
  /// Server sequence id (a numeric string).
  public var sequenceId: String?
  /// Message id the sender minted (a UUID).
  public var messageId: String?
  public var senderId: String?
  public var conversationId: String?
  /// Server-assigned creation time in milliseconds.
  public var createdAtMilliseconds: Int64?
}

/// A decrypted event.
public enum XChatEvent: Sendable {
  case message(Message)
  case keyChange(KeyChange)
  case typing(Typing)
  case failure(Failure)
  /// An event this SDK does not process (deletes, read markers, group and
  /// conversation-metadata changes, pins, Grok, …). `verified` reports
  /// whether its signature was checked, when its type has a payload this
  /// SDK can rebuild.
  case unsupported(UnsupportedEvent)
}

/// A decrypted message.
public struct Message: Sendable, Equatable {
  public var meta: EventMeta
  public var content: MessageContent
  public var conversationKeyVersion: String?
  /// Whether the event's signature verified against the supplied key.
  public var verified: Bool
  public var shouldNotify: Bool?
  public var ttlMilliseconds: Int64?
  public var attachments: [AttachmentInfo]
  /// The media hash keys of the message's files, in attachment order.
  public var mediaHashes: [MediaHashReference]
  /// Set when the message quotes another message: whether the quoted
  /// original matched the preview.
  public var replyPreviewValidation: ReplyPreviewValidation?

  /// The message's text, when it is a text message.
  public var text: String? {
    guard case .text(let content) = content else { return nil }
    return content.text
  }
}

/// What a decrypted message carries.
public enum MessageContent: Sendable, Equatable {
  case text(TextContent)
  case reaction(emoji: String, targetMessageSequenceId: String)
  case reactionRemoved(emoji: String, targetMessageSequenceId: String)
  case edit(
    targetMessageSequenceId: String,
    targetMessageId: String?,
    updatedText: String,
    entities: [RichTextEntityInfo]?)
  case markRead
  case markUnread
  case unknown
}

/// A text message's contents.
public struct TextContent: Sendable, Equatable {
  public var text: String
  public var entities: [RichTextEntityInfo]?
  public var attachments: [AttachmentInfo]
  public var replyingToPreview: ReplyPreview?
  public var forwardedMessage: ForwardedContent?
  public var sentFrom: Int32?
  public var quickReply: QuickReplyInfo?
  public var callToActions: [CallToActionInfo]?
}

/// A span of text marked as a hashtag, mention, link, and so on. Offsets
/// count UTF-8 bytes, `start` inclusive and `end` exclusive.
public struct RichTextEntityInfo: Sendable, Equatable {
  public var startIndex: Int32?
  public var endIndex: Int32?
  public var kind: EntityKind?
}

public enum EntityKind: String, Sendable, Equatable {
  case hashtag
  case cashtag
  case mention
  case url
  case email
  case address
  case phoneNumber
}

/// One attachment of a message.
public enum AttachmentInfo: Sendable, Equatable {
  case media(MediaAttachmentInfo)
  case url(UrlAttachmentInfo)
  case post(PostAttachmentInfo)
  case unifiedCard(UnifiedCardAttachmentInfo)
  case money(MoneyAttachmentInfo)
}

/// An encrypted file attached to a message.
public struct MediaAttachmentInfo: Sendable, Equatable {
  public var mediaHashKey: String?
  public var dimensions: MediaDimensionsInfo?
  /// `image`, `gif`, `video`, `audio`, `file`, or `svg`.
  public var mediaType: String?
  public var durationMilliseconds: Int64?
  public var filesizeBytes: Int64?
  public var filename: String?
  public var attachmentId: String?
  public var legacyMediaURLHTTPS: String?
  public var legacyMediaPreviewURL: String?
  /// SHA-256 of the decrypted media bytes, when the sender included it.
  public var plaintextSHA256: [UInt8]?
}

public struct MediaDimensionsInfo: Sendable, Equatable {
  public var width: Int64?
  public var height: Int64?
}

/// A link card, with its images' media hash keys.
public struct UrlAttachmentInfo: Sendable, Equatable {
  public var url: String?
  public var bannerImageMediaHashKey: String?
  public var faviconImageMediaHashKey: String?
  public var displayTitle: String?
  public var attachmentId: String?
}

public struct PostAttachmentInfo: Sendable, Equatable {
  public var restId: String?
  public var postURL: String?
  public var attachmentId: String?
}

public struct UnifiedCardAttachmentInfo: Sendable, Equatable {
  public var url: String?
  public var attachmentId: String?
}

public struct MoneyAttachmentInfo: Sendable, Equatable {
  public var fallbackText: String?
}

/// A media hash key a message references.
public struct MediaHashReference: Sendable, Equatable {
  /// Where the reference came from: `media`, `url_banner`, or `url_favicon`.
  public var source: String
  public var mediaHashKey: String
}

/// A quoted message shown above a reply.
public struct ReplyPreview: Sendable, Equatable {
  public var senderId: String?
  public var messageText: String?
  public var entities: [RichTextEntityInfo]?
  public var attachments: [AttachmentInfo]?
  public var senderDisplayName: String?
  /// Always nil for decoded previews because the source signature does not cover sequence IDs.
  public var messageSequenceId: String?
  public var messageId: String?
  public var attachmentId: String?
  /// Whether the preview embeds the signed source event, which is what
  /// lets a recipient validate it.
  public var embedsSourceEvent: Bool
}

/// Whether a reply preview matched the signed original it quotes.
public enum ReplyPreviewValidation: Sendable, Equatable {
  case valid
  case invalid
}

public struct ForwardedContent: Sendable, Equatable {
  public var text: String?
  public var entities: [RichTextEntityInfo]?
}

/// A quick reply: the options a message offers or the answer to one.
public struct QuickReplyInfo: Sendable, Equatable {
  public enum Content: Sendable, Equatable {
    case request(id: String?, options: [QuickReplyOptionInfo])
    case response(requestId: String?, metadata: String?, selectedOptionId: String?)
  }

  public var content: Content

  public init(content: Content) {
    self.content = content
  }
}

public struct QuickReplyOptionInfo: Sendable, Equatable {
  public var id: String?
  public var label: String?
  public var metadata: String?
  public var optionDescription: String?

  public init(
    id: String? = nil, label: String? = nil, metadata: String? = nil,
    optionDescription: String? = nil
  ) {
    self.id = id
    self.label = label
    self.metadata = metadata
    self.optionDescription = optionDescription
  }
}

public struct CallToActionInfo: Sendable, Equatable {
  public var label: String?
  public var url: String?
}

/// A conversation-key change: the new key version and each participant's
/// ECIES-encrypted copy of the key.
public struct KeyChange: Sendable {
  public var meta: EventMeta
  public var conversationKeyVersion: String
  public var verified: Bool
  public var participantKeys: [ParticipantKey]
}

public struct ParticipantKey: Sendable, Equatable {
  public var userId: String
  public var encryptedConversationKey: String
  public var publicKeyVersion: String
}

/// Someone typing or recording in a conversation.
public struct Typing: Sendable {
  public var meta: EventMeta
  public var activityType: Int32?
  public var createdAtMilliseconds: String?
}

/// Why the backend refused a message.
public struct Failure: Sendable {
  public var meta: EventMeta
  public var failureType: Int32?
  public var rateLimitTier: Int32?
}

/// An event this SDK does not process.
public struct UnsupportedEvent: Sendable {
  public var meta: EventMeta
  public var verified: Bool
}

/// Conversation keys by version, and the newest version a verified key
/// change established.
public struct ConversationKeySet: Sendable {
  public var keys: [String: [UInt8]]
  public var latestVersion: String?
}

/// One decrypted event and the base64 it came from.
public struct DecryptedEvent: Sendable {
  public var event: XChatEvent
  public var originalB64: String?
}

/// The batch decryption result: decrypted events, adopted conversation
/// keys, and per-index error messages for the events left out.
public struct DecryptEventsResult: Sendable {
  public var events: [DecryptedEvent]
  public var conversationKeys: ConversationKeySet
  public var errors: [Int: String]
}

/// A signing key the verifier knows, with the optional identity-key binding
/// that registration publishes for it.
public struct SigningKeyEntry: Sendable, Equatable {
  /// User the key belongs to; events verify only against their sender's
  /// keys.
  public var userId: String
  /// Version the key was published as.
  public var publicKeyVersion: String
  /// Base64 SEC1 (or SPKI DER) signing public key.
  public var publicKey: String
  /// Base64 identity public key the signing key is bound to.
  public var identityPublicKey: String?
  /// Base64 signature of the identity key bytes by the signing key.
  public var identityPublicKeySignature: String?
  /// Base64 signature of the signing key SPKI DER by the identity key.
  public var signingPublicKeySignature: String?

  public init(
    userId: String, publicKeyVersion: String, publicKey: String,
    identityPublicKey: String? = nil, identityPublicKeySignature: String? = nil,
    signingPublicKeySignature: String? = nil
  ) {
    self.userId = userId
    self.publicKeyVersion = publicKeyVersion
    self.publicKey = publicKey
    self.identityPublicKey = identityPublicKey
    self.identityPublicKeySignature = identityPublicKeySignature
    self.signingPublicKeySignature = signingPublicKeySignature
  }
}
