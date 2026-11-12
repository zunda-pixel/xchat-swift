/// Per-message and per-attachment keys.
///
/// A message whose `contents_encryption_version` is 1 or more is encrypted
/// under a key derived for that message from the conversation key, and each
/// of its attachments under a key derived from the message key. Messages
/// without a version use the conversation key for both.

private let messageKeySalt = "xchat-message-key"
private let attachmentKeySalt = "xchat-attachment-key"
private let mediaMessageIdSalt = "chat-xdk-media-message-id"

/// The `contents_encryption_version` of the messages this SDK sends.
let sendContentsEncryptionVersion = 1

/// Whether a message with this `contents_encryption_version` uses a message
/// key. Unset, zero, and negative versions use the conversation key.
func usesMessageKey(_ contentsEncryptionVersion: Int?) -> Bool {
    guard let version = contentsEncryptionVersion else { return false }
    return version >= 1
}

/// Derives a message's 32-byte key from its conversation key, sender, and
/// message id. The HKDF info is `<sender id>:<message id>` with the sender
/// id in canonical decimal form, so a sender id that is not an integer has
/// no message key.
func deriveMessageKey(
    conversationKey: [UInt8],
    senderId: String,
    messageId: String
) throws -> [UInt8] {
    guard let sender = Int64(senderId) else {
        throw XChatError.decryption(
            "message key needs a numeric sender id, got '\(senderId)'")
    }
    let info = "\(sender):\(messageId)"
    return try hkdfWithInfo(
        secret: conversationKey, salt: messageKeySalt, info: Array(info.utf8), length: 32)
}

/// Derives an attachment's 32-byte key from its message key and attachment
/// id.
func deriveAttachmentKey(messageKey: [UInt8], attachmentId: String) throws -> [UInt8] {
    try hkdfWithInfo(
        secret: messageKey, salt: attachmentKeySalt, info: Array(attachmentId.utf8), length: 32)
}

/// The id an attachment's key is derived from: the attachment's own id when
/// set (an empty id counts), otherwise the message id for the first
/// attachment and `<message id>#<index>` for later ones.
func resolveAttachmentId(storedId: String?, messageId: String, index: Int) -> String {
    guard let id = storedId else {
        return index == 0 ? messageId : "\(messageId)#\(index)"
    }
    return id
}

/// The id of an outgoing v1 message with files, derived from what
/// identifies the message: the conversation key and its version, the
/// sender, the conversation, and the media hash keys of its files in order.
/// Every upload has its own media hash key, so the id is unique to the
/// message; building the same message again gives the same id, which keeps
/// its uploaded files valid.
func deriveMediaMessageId(
    conversationKey: [UInt8],
    conversationKeyVersion: String,
    senderId: String,
    conversationId: String,
    mediaHashKeys: [String]
) throws -> String {
    // Length-prefixed fields: no two distinct inputs share an encoding.
    var info: [UInt8] = []
    let fields = [conversationKeyVersion, senderId, conversationId] + mediaHashKeys
    for field in fields {
        let length = UInt64(field.utf8.count)
        info += [
            UInt8(truncatingIfNeeded: length >> 56),
            UInt8(truncatingIfNeeded: length >> 48),
            UInt8(truncatingIfNeeded: length >> 40),
            UInt8(truncatingIfNeeded: length >> 32),
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length),
        ]
        info += Array(field.utf8)
    }
    var bytes = try hkdfWithInfo(
        secret: conversationKey, salt: mediaMessageIdSalt, info: info, length: 16)

    // Version 4, RFC 4122 variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    return formatUUID(bytes)
}

/// Formats 16 bytes as a lowercase, hyphenated UUID. The caller sets the
/// version and variant bits.
func formatUUID(_ bytes: [UInt8]) -> String {
    precondition(bytes.count == 16, "UUIDs are 16 bytes")
    let hex = Hex.encode(bytes)
    return "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-"
        + "\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
}
