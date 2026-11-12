/// The decrypted payload of a message: a Thrift `MessageEntryHolder`
/// carrying one `MessageEntryContents` variant.

struct MessageEntryHolder: Sendable, Equatable {
    var contents: MessageEntryContents?

    static func read(_ reader: inout ThriftReader) throws -> MessageEntryHolder {
        var holder = MessageEntryHolder()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if field.id == 1 {
                try expectField(field, .structure, "contents")
                holder.contents = try MessageEntryContents.read(&reader)
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return holder
    }

    func write(to writer: inout ThriftWriter) {
        if let contents {
            writer.writeFieldBegin(id: 1, type: .structure)
            contents.write(to: &writer)
        }
        writer.writeFieldStop()
    }
}

/// The payload variant a message carries.
enum MessageEntryContents: Sendable, Equatable {
    case message(MessageContents)
    case reactionAdd(MessageReactionAdd)
    case reactionRemove(MessageReactionRemove)
    case messageEdit(MessageEdit)
    case markConversationRead(MarkConversationRead)
    case markConversationUnread(MarkConversationUnread)
    /// A variant this SDK does not model, identified by its union field id.
    case unsupported(fieldId: Int16)

    static func read(_ reader: inout ThriftReader) throws -> MessageEntryContents? {
        var contents: MessageEntryContents?
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if contents == nil {
                switch field.id {
                case 1:
                    try expectField(field, .structure, "message")
                    contents = .message(try MessageContents.read(&reader))
                case 2:
                    try expectField(field, .structure, "reaction_add")
                    contents = .reactionAdd(try MessageReactionAdd.read(&reader))
                case 3:
                    try expectField(field, .structure, "reaction_remove")
                    contents = .reactionRemove(try MessageReactionRemove.read(&reader))
                case 4:
                    try expectField(field, .structure, "message_edit")
                    contents = .messageEdit(try MessageEdit.read(&reader))
                case 5:
                    try expectField(field, .structure, "mark_conversation_read")
                    contents = .markConversationRead(try MarkConversationRead.read(&reader))
                case 6:
                    try expectField(field, .structure, "mark_conversation_unread")
                    contents = .markConversationUnread(try MarkConversationUnread.read(&reader))
                default:
                    contents = .unsupported(fieldId: field.id)
                    try reader.skip(field.type)
                }
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return contents
    }

    func write(to writer: inout ThriftWriter) {
        switch self {
        case .message(let contents):
            writer.writeFieldBegin(id: 1, type: .structure)
            contents.write(to: &writer)
        case .reactionAdd(let reaction):
            writer.writeFieldBegin(id: 2, type: .structure)
            reaction.write(to: &writer)
        case .reactionRemove(let reaction):
            writer.writeFieldBegin(id: 3, type: .structure)
            reaction.write(to: &writer)
        case .messageEdit(let edit):
            writer.writeFieldBegin(id: 4, type: .structure)
            edit.write(to: &writer)
        case .markConversationRead(let marker):
            writer.writeFieldBegin(id: 5, type: .structure)
            marker.write(to: &writer)
        case .markConversationUnread(let marker):
            writer.writeFieldBegin(id: 6, type: .structure)
            marker.write(to: &writer)
        case .unsupported:
            break
        }
        writer.writeFieldStop()
    }
}

/// A text message's contents: text, rich-text entities, attachments, a
/// reply preview, a forwarded body, and an optional quick reply.
struct MessageContents: Sendable, Equatable {
    var messageText: String?
    var entities: [RichTextEntity]?
    var attachments: [MessageAttachment]?
    var replyingToPreview: ReplyingToPreview?
    var forwardedMessage: ForwardedMessage?
    var sentFrom: Int32?
    var quickReply: QuickReply?
    var callToActions: [CallToAction]?
    var additionalFields: [String: String]?

    static func read(_ reader: inout ThriftReader) throws -> MessageContents {
        var contents = MessageContents()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                contents.messageText = try readStringField(field, "message_text", &reader)
            case 2:
                contents.entities = try readStructList(field, "entities", &reader) {
                    try RichTextEntity.read(&$0)
                }
            case 3:
                contents.attachments = try readStructList(field, "attachments", &reader) {
                    guard let attachment = try MessageAttachment.read(&$0) else {
                        throw XChatError.parse("message attachment carries no variant")
                    }
                    return attachment
                }
            case 4:
                try expectField(field, .structure, "replying_to_preview")
                contents.replyingToPreview = try ReplyingToPreview.read(&reader)
            case 6:
                try expectField(field, .structure, "forwarded_message")
                contents.forwardedMessage = try ForwardedMessage.read(&reader)
            case 7:
                contents.sentFrom = try readI32Field(field, "sent_from", &reader)
            case 8:
                try expectField(field, .structure, "quick_reply")
                contents.quickReply = try QuickReply.read(&reader)
            case 9:
                contents.callToActions = try readStructList(field, "ctas", &reader) {
                    try CallToAction.read(&$0)
                }
            case 10:
                contents.additionalFields = try readStringMap(
                    field, "additional_fields", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return contents
    }

    func write(to writer: inout ThriftWriter) {
        if let messageText {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(messageText)
        }
        if let entities {
            writer.writeFieldBegin(id: 2, type: .list)
            writer.writeListBegin(elementType: .structure, count: entities.count)
            for entity in entities {
                entity.write(to: &writer)
            }
        }
        if let attachments {
            writer.writeFieldBegin(id: 3, type: .list)
            writer.writeListBegin(elementType: .structure, count: attachments.count)
            for attachment in attachments {
                attachment.write(to: &writer)
            }
        }
        if let replyingToPreview {
            writer.writeFieldBegin(id: 4, type: .structure)
            replyingToPreview.write(to: &writer)
        }
        if let forwardedMessage {
            writer.writeFieldBegin(id: 6, type: .structure)
            forwardedMessage.write(to: &writer)
        }
        if let sentFrom {
            writer.writeFieldBegin(id: 7, type: .i32)
            writer.writeI32(sentFrom)
        }
        if let quickReply {
            writer.writeFieldBegin(id: 8, type: .structure)
            quickReply.write(to: &writer)
        }
        if let callToActions {
            writer.writeFieldBegin(id: 9, type: .list)
            writer.writeListBegin(elementType: .structure, count: callToActions.count)
            for callToAction in callToActions {
                callToAction.write(to: &writer)
            }
        }
        if let additionalFields {
            writer.writeFieldBegin(id: 10, type: .map)
            writer.writeMapBegin(
                keyType: .binary, valueType: .binary, count: additionalFields.count)
            for (key, value) in additionalFields {
                writer.writeString(key)
                writer.writeString(value)
            }
        }
        writer.writeFieldStop()
    }
}

/// A span of the text marked as a hashtag, mention, link, and so on.
struct RichTextEntity: Sendable, Equatable {
    var startIndex: Int32?
    var endIndex: Int32?
    var content: RichTextContent?

    static func read(_ reader: inout ThriftReader) throws -> RichTextEntity {
        var entity = RichTextEntity()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                entity.startIndex = try readI32Field(field, "start_index", &reader)
            case 2:
                entity.endIndex = try readI32Field(field, "end_index", &reader)
            case 3:
                try expectField(field, .structure, "content")
                entity.content = try RichTextContent.read(&reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return entity
    }

    func write(to writer: inout ThriftWriter) {
        if let startIndex {
            writer.writeFieldBegin(id: 1, type: .i32)
            writer.writeI32(startIndex)
        }
        if let endIndex {
            writer.writeFieldBegin(id: 2, type: .i32)
            writer.writeI32(endIndex)
        }
        if let content {
            writer.writeFieldBegin(id: 3, type: .structure)
            content.write(to: &writer)
        }
        writer.writeFieldStop()
    }
}

/// What kind of entity a `RichTextEntity` marks. Every variant carries an
/// empty struct; the tag alone has meaning.
enum RichTextContent: Sendable, Equatable {
    case hashtag
    case cashtag
    case mention
    case url
    case email
    case address
    case phoneNumber
    case unsupported(fieldId: Int16)

    static func read(_ reader: inout ThriftReader) throws -> RichTextContent? {
        var content: RichTextContent?
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if content == nil {
                switch field.id {
                case 1: content = .hashtag
                case 2: content = .cashtag
                case 3: content = .mention
                case 4: content = .url
                case 5: content = .email
                case 6: content = .address
                case 7: content = .phoneNumber
                default: content = .unsupported(fieldId: field.id)
                }
                try reader.skip(field.type)
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return content
    }

    func write(to writer: inout ThriftWriter) {
        let id: Int16
        switch self {
        case .hashtag: id = 1
        case .cashtag: id = 2
        case .mention: id = 3
        case .url: id = 4
        case .email: id = 5
        case .address: id = 6
        case .phoneNumber: id = 7
        case .unsupported: return
        }
        writer.writeFieldBegin(id: id, type: .structure)
        writer.writeFieldStop()
        writer.writeFieldStop()
    }
}

/// One attachment of a message.
enum MessageAttachment: Sendable, Equatable {
    case media(MediaAttachment)
    case post(PostAttachment)
    case url(UrlAttachment)
    case unifiedCard(UnifiedCardAttachment)
    case money(MoneyAttachment)
    /// Jetfuel, payment receipts and bot messages, which this SDK does not
    /// model, identified by their union field id.
    case unsupported(fieldId: Int16)

    static func read(_ reader: inout ThriftReader) throws -> MessageAttachment? {
        var attachment: MessageAttachment?
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if attachment == nil {
                switch field.id {
                case 1:
                    try expectField(field, .structure, "media")
                    attachment = .media(try MediaAttachment.read(&reader))
                case 2:
                    try expectField(field, .structure, "post")
                    attachment = .post(try PostAttachment.read(&reader))
                case 3:
                    try expectField(field, .structure, "url")
                    attachment = .url(try UrlAttachment.read(&reader))
                case 4:
                    try expectField(field, .structure, "unified_card")
                    attachment = .unifiedCard(try UnifiedCardAttachment.read(&reader))
                case 5:
                    try expectField(field, .structure, "money")
                    attachment = .money(try MoneyAttachment.read(&reader))
                default:
                    attachment = .unsupported(fieldId: field.id)
                    try reader.skip(field.type)
                }
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return attachment
    }

    func write(to writer: inout ThriftWriter) {
        switch self {
        case .media(let media):
            writer.writeFieldBegin(id: 1, type: .structure)
            media.write(to: &writer)
        case .post(let post):
            writer.writeFieldBegin(id: 2, type: .structure)
            post.write(to: &writer)
        case .url(let url):
            writer.writeFieldBegin(id: 3, type: .structure)
            url.write(to: &writer)
        case .unifiedCard(let card):
            writer.writeFieldBegin(id: 4, type: .structure)
            card.write(to: &writer)
        case .money(let money):
            writer.writeFieldBegin(id: 5, type: .structure)
            money.write(to: &writer)
        case .unsupported:
            break
        }
        writer.writeFieldStop()
    }
}

/// An encrypted file attached to a message.
struct MediaAttachment: Sendable, Equatable {
    var mediaHashKey: String?
    var dimensions: MediaDimensions?
    var type: MediaType?
    var durationMilliseconds: Int64?
    var filesizeBytes: Int64?
    var filename: String?
    var attachmentId: String?
    var legacyMediaURLHTTPS: String?
    var legacyMediaPreviewURL: String?
    var grokTag: String?
    var plaintextSHA256: [UInt8]?

    static func read(_ reader: inout ThriftReader) throws -> MediaAttachment {
        var media = MediaAttachment()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                media.mediaHashKey = try readStringField(field, "media_hash_key", &reader)
            case 2:
                try expectField(field, .structure, "dimensions")
                media.dimensions = try MediaDimensions.read(&reader)
            case 3:
                media.type = MediaType(rawValue: try readI32Field(field, "type", &reader))
            case 4:
                media.durationMilliseconds = try readI64Field(
                    field, "duration_millis", &reader)
            case 5:
                media.filesizeBytes = try readI64Field(field, "filesize_bytes", &reader)
            case 6:
                media.filename = try readStringField(field, "filename", &reader)
            case 7:
                media.attachmentId = try readStringField(field, "attachment_id", &reader)
            case 8:
                media.legacyMediaURLHTTPS = try readStringField(
                    field, "legacy_media_url_https", &reader)
            case 9:
                media.legacyMediaPreviewURL = try readStringField(
                    field, "legacy_media_preview_url", &reader)
            case 10:
                media.grokTag = try readStringField(field, "grok_tag", &reader)
            case 11:
                media.plaintextSHA256 = try readBinaryField(
                    field, "plaintext_sha256", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return media
    }

    func write(to writer: inout ThriftWriter) {
        if let mediaHashKey {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(mediaHashKey)
        }
        if let dimensions {
            writer.writeFieldBegin(id: 2, type: .structure)
            dimensions.write(to: &writer)
        }
        if let type {
            writer.writeFieldBegin(id: 3, type: .i32)
            writer.writeI32(type.rawValue)
        }
        if let durationMilliseconds {
            writer.writeFieldBegin(id: 4, type: .i64)
            writer.writeI64(durationMilliseconds)
        }
        if let filesizeBytes {
            writer.writeFieldBegin(id: 5, type: .i64)
            writer.writeI64(filesizeBytes)
        }
        if let filename {
            writer.writeFieldBegin(id: 6, type: .binary)
            writer.writeString(filename)
        }
        if let attachmentId {
            writer.writeFieldBegin(id: 7, type: .binary)
            writer.writeString(attachmentId)
        }
        if let legacyMediaURLHTTPS {
            writer.writeFieldBegin(id: 8, type: .binary)
            writer.writeString(legacyMediaURLHTTPS)
        }
        if let legacyMediaPreviewURL {
            writer.writeFieldBegin(id: 9, type: .binary)
            writer.writeString(legacyMediaPreviewURL)
        }
        if let grokTag {
            writer.writeFieldBegin(id: 10, type: .binary)
            writer.writeString(grokTag)
        }
        if let plaintextSHA256 {
            writer.writeFieldBegin(id: 11, type: .binary)
            writer.writeBinary(plaintextSHA256)
        }
        writer.writeFieldStop()
    }
}

/// The media kind of an attachment.
enum MediaType: Int32, Sendable {
    case image = 1
    case gif = 2
    case video = 3
    case audio = 4
    case file = 5
    case svg = 6
}

struct MediaDimensions: Sendable, Equatable {
    var width: Int64?
    var height: Int64?

    static func read(_ reader: inout ThriftReader) throws -> MediaDimensions {
        var dimensions = MediaDimensions()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                dimensions.width = try readI64Field(field, "width", &reader)
            case 2:
                dimensions.height = try readI64Field(field, "height", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return dimensions
    }

    func write(to writer: inout ThriftWriter) {
        if let width {
            writer.writeFieldBegin(id: 1, type: .i64)
            writer.writeI64(width)
        }
        if let height {
            writer.writeFieldBegin(id: 2, type: .i64)
            writer.writeI64(height)
        }
        writer.writeFieldStop()
    }
}

/// A post attachment, hydrated on the receiver side.
struct PostAttachment: Sendable, Equatable {
    var restId: String?
    var postURL: String?
    var attachmentId: String?

    static func read(_ reader: inout ThriftReader) throws -> PostAttachment {
        var post = PostAttachment()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                post.restId = try readStringField(field, "rest_id", &reader)
            case 2:
                post.postURL = try readStringField(field, "post_url", &reader)
            case 3:
                post.attachmentId = try readStringField(field, "attachment_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return post
    }

    func write(to writer: inout ThriftWriter) {
        if let restId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(restId)
        }
        if let postURL {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(postURL)
        }
        if let attachmentId {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(attachmentId)
        }
        writer.writeFieldStop()
    }
}

/// A link card, with its images' media hash keys.
struct UrlAttachment: Sendable, Equatable {
    var url: String?
    var bannerImage: UrlAttachmentImage?
    var faviconImage: UrlAttachmentImage?
    var displayTitle: String?
    var attachmentId: String?

    static func read(_ reader: inout ThriftReader) throws -> UrlAttachment {
        var attachment = UrlAttachment()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                attachment.url = try readStringField(field, "url", &reader)
            case 2:
                try expectField(field, .structure, "banner_image_media_hash_key")
                attachment.bannerImage = try UrlAttachmentImage.read(&reader)
            case 3:
                try expectField(field, .structure, "favicon_image_media_hash_key")
                attachment.faviconImage = try UrlAttachmentImage.read(&reader)
            case 4:
                attachment.displayTitle = try readStringField(field, "display_title", &reader)
            case 5:
                attachment.attachmentId = try readStringField(field, "attachment_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return attachment
    }

    func write(to writer: inout ThriftWriter) {
        if let url {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(url)
        }
        if let bannerImage {
            writer.writeFieldBegin(id: 2, type: .structure)
            bannerImage.write(to: &writer)
        }
        if let faviconImage {
            writer.writeFieldBegin(id: 3, type: .structure)
            faviconImage.write(to: &writer)
        }
        if let displayTitle {
            writer.writeFieldBegin(id: 4, type: .binary)
            writer.writeString(displayTitle)
        }
        if let attachmentId {
            writer.writeFieldBegin(id: 5, type: .binary)
            writer.writeString(attachmentId)
        }
        writer.writeFieldStop()
    }
}

/// One image of a link card.
struct UrlAttachmentImage: Sendable, Equatable {
    var mediaHashKey: String?
    var filesizeBytes: Int64?
    var filename: String?
    var dimensions: MediaDimensions?

    static func read(_ reader: inout ThriftReader) throws -> UrlAttachmentImage {
        var image = UrlAttachmentImage()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                image.mediaHashKey = try readStringField(field, "media_hash_key", &reader)
            case 2:
                image.filesizeBytes = try readI64Field(field, "filesize_bytes", &reader)
            case 3:
                image.filename = try readStringField(field, "filename", &reader)
            case 4:
                try expectField(field, .structure, "dimensions")
                image.dimensions = try MediaDimensions.read(&reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return image
    }

    func write(to writer: inout ThriftWriter) {
        if let mediaHashKey {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(mediaHashKey)
        }
        if let filesizeBytes {
            writer.writeFieldBegin(id: 2, type: .i64)
            writer.writeI64(filesizeBytes)
        }
        if let filename {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(filename)
        }
        if let dimensions {
            writer.writeFieldBegin(id: 4, type: .structure)
            dimensions.write(to: &writer)
        }
        writer.writeFieldStop()
    }
}

/// A unified card, hydrated on the receiver side.
struct UnifiedCardAttachment: Sendable, Equatable {
    var url: String?
    var attachmentId: String?

    static func read(_ reader: inout ThriftReader) throws -> UnifiedCardAttachment {
        var card = UnifiedCardAttachment()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                card.url = try readStringField(field, "url", &reader)
            case 2:
                card.attachmentId = try readStringField(field, "attachment_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return card
    }

    func write(to writer: inout ThriftWriter) {
        if let url {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(url)
        }
        if let attachmentId {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(attachmentId)
        }
        writer.writeFieldStop()
    }
}

/// A peer-to-peer payment message.
struct MoneyAttachment: Sendable, Equatable {
    var fallbackText: String?
    var payload: [UInt8]?

    static func read(_ reader: inout ThriftReader) throws -> MoneyAttachment {
        var money = MoneyAttachment()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                money.fallbackText = try readStringField(field, "fallbackText", &reader)
            case 2:
                money.payload = try readBinaryField(field, "payload", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return money
    }

    func write(to writer: inout ThriftWriter) {
        if let fallbackText {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(fallbackText)
        }
        if let payload {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeBinary(payload)
        }
        writer.writeFieldStop()
    }
}

/// A quoted message shown above a reply.
struct ReplyingToPreview: Sendable, Equatable {
    var senderId: Int64?
    var messageText: String?
    var entities: [RichTextEntity]?
    var attachments: [MessageAttachment]?
    var senderDisplayName: String?
    var messageSequenceId: String?
    var messageId: String?
    var attachmentId: String?
    /// The source message event some previews embed so recipients can
    /// validate the preview against the signed original.
    var rawEventMessageCreate: MessageEvent?
    /// The edit event a preview of an edited message embeds.
    var rawEventEditMessage: MessageEvent?
    /// Key-change events the preview embeds for its source's key.
    var rawEventKeyChanges: [MessageEvent]?
    /// The per-message key the preview carries for its source event.
    var rawEventMessageKey: [UInt8]?
    /// The per-message key the preview carries for its edit event.
    var rawEventEditMessageKey: [UInt8]?

    static func read(_ reader: inout ThriftReader) throws -> ReplyingToPreview {
        var preview = ReplyingToPreview()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                preview.senderId = try readI64Field(field, "sender_id", &reader)
            case 2:
                preview.messageText = try readStringField(field, "message_text", &reader)
            case 3:
                preview.entities = try readStructList(field, "entities", &reader) {
                    try RichTextEntity.read(&$0)
                }
            case 4:
                preview.attachments = try readStructList(field, "attachments", &reader) {
                    guard let attachment = try MessageAttachment.read(&$0) else {
                        throw XChatError.parse("preview attachment carries no variant")
                    }
                    return attachment
                }
            case 5:
                preview.senderDisplayName = try readStringField(
                    field, "sender_display_name", &reader)
            case 6:
                preview.messageSequenceId = try readStringField(
                    field, "replying_to_message_sequence_id", &reader)
            case 7:
                preview.messageId = try readStringField(
                    field, "replying_to_message_id", &reader)
            case 12:
                preview.attachmentId = try readStringField(
                    field, "replying_to_attachment_id", &reader)
            case 8:
                try expectField(field, .structure, "raw_event_message_create")
                preview.rawEventMessageCreate = try MessageEvent.read(&reader)
            case 9:
                try expectField(field, .structure, "raw_event_edit_message")
                preview.rawEventEditMessage = try MessageEvent.read(&reader)
            case 10:
                preview.rawEventKeyChanges = try readStructList(
                    field, "raw_event_ckces", &reader
                ) {
                    try MessageEvent.read(&$0)
                }
            case 13:
                preview.rawEventMessageKey = try readBinaryField(
                    field, "raw_event_message_key", &reader)
            case 14:
                preview.rawEventEditMessageKey = try readBinaryField(
                    field, "raw_event_edit_message_key", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return preview
    }

    func write(to writer: inout ThriftWriter) {
        if let senderId {
            writer.writeFieldBegin(id: 1, type: .i64)
            writer.writeI64(senderId)
        }
        if let messageText {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(messageText)
        }
        if let entities {
            writer.writeFieldBegin(id: 3, type: .list)
            writer.writeListBegin(elementType: .structure, count: entities.count)
            for entity in entities {
                entity.write(to: &writer)
            }
        }
        if let attachments {
            writer.writeFieldBegin(id: 4, type: .list)
            writer.writeListBegin(elementType: .structure, count: attachments.count)
            for attachment in attachments {
                attachment.write(to: &writer)
            }
        }
        if let senderDisplayName {
            writer.writeFieldBegin(id: 5, type: .binary)
            writer.writeString(senderDisplayName)
        }
        if let messageSequenceId {
            writer.writeFieldBegin(id: 6, type: .binary)
            writer.writeString(messageSequenceId)
        }
        if let messageId {
            writer.writeFieldBegin(id: 7, type: .binary)
            writer.writeString(messageId)
        }
        if let attachmentId {
            writer.writeFieldBegin(id: 12, type: .binary)
            writer.writeString(attachmentId)
        }
        if let rawEventMessageCreate {
            writer.writeFieldBegin(id: 8, type: .structure)
            rawEventMessageCreate.write(to: &writer)
        }
        if let rawEventEditMessage {
            writer.writeFieldBegin(id: 9, type: .structure)
            rawEventEditMessage.write(to: &writer)
        }
        if let rawEventKeyChanges {
            writer.writeFieldBegin(id: 10, type: .list)
            writer.writeListBegin(elementType: .structure, count: rawEventKeyChanges.count)
            for event in rawEventKeyChanges {
                event.write(to: &writer)
            }
        }
        if let rawEventMessageKey {
            writer.writeFieldBegin(id: 13, type: .binary)
            writer.writeBinary(rawEventMessageKey)
        }
        if let rawEventEditMessageKey {
            writer.writeFieldBegin(id: 14, type: .binary)
            writer.writeBinary(rawEventEditMessageKey)
        }
        writer.writeFieldStop()
    }
}

/// A forwarded message body.
struct ForwardedMessage: Sendable, Equatable {
    var messageText: String?
    var entities: [RichTextEntity]?

    static func read(_ reader: inout ThriftReader) throws -> ForwardedMessage {
        var forwarded = ForwardedMessage()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                forwarded.messageText = try readStringField(field, "message_text", &reader)
            case 2:
                forwarded.entities = try readStructList(field, "entities", &reader) {
                    try RichTextEntity.read(&$0)
                }
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return forwarded
    }

    func write(to writer: inout ThriftWriter) {
        if let messageText {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(messageText)
        }
        if let entities {
            writer.writeFieldBegin(id: 2, type: .list)
            writer.writeListBegin(elementType: .structure, count: entities.count)
            for entity in entities {
                entity.write(to: &writer)
            }
        }
        writer.writeFieldStop()
    }
}

/// A quick reply: either the options a message offers or the chosen one.
enum QuickReply: Sendable, Equatable {
    case request(QuickReplyRequest)
    case response(QuickReplyResponse)
    case unsupported(fieldId: Int16)

    static func read(_ reader: inout ThriftReader) throws -> QuickReply? {
        var quickReply: QuickReply?
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if quickReply == nil {
                switch field.id {
                case 1:
                    try expectField(field, .structure, "request")
                    quickReply = .request(try QuickReplyRequest.read(&reader))
                case 2:
                    try expectField(field, .structure, "response")
                    quickReply = .response(try QuickReplyResponse.read(&reader))
                default:
                    quickReply = .unsupported(fieldId: field.id)
                    try reader.skip(field.type)
                }
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return quickReply
    }

    func write(to writer: inout ThriftWriter) {
        switch self {
        case .request(let request):
            writer.writeFieldBegin(id: 1, type: .structure)
            request.write(to: &writer)
        case .response(let response):
            writer.writeFieldBegin(id: 2, type: .structure)
            response.write(to: &writer)
        case .unsupported:
            break
        }
        writer.writeFieldStop()
    }
}

/// A quick-reply request: the options a message offers.
struct QuickReplyRequest: Sendable, Equatable {
    var options: QuickReplyOptionsRequest?

    static func read(_ reader: inout ThriftReader) throws -> QuickReplyRequest {
        var request = QuickReplyRequest()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if field.id == 1 {
                try expectField(field, .structure, "options")
                request.options = try QuickReplyOptionsRequest.read(&reader)
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return request
    }

    func write(to writer: inout ThriftWriter) {
        if let options {
            writer.writeFieldBegin(id: 1, type: .structure)
            options.write(to: &writer)
        }
        writer.writeFieldStop()
    }
}

/// A quick-reply answer, naming the chosen option.
struct QuickReplyResponse: Sendable, Equatable {
    var options: QuickReplyOptionsResponse?

    static func read(_ reader: inout ThriftReader) throws -> QuickReplyResponse {
        var response = QuickReplyResponse()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if field.id == 1 {
                try expectField(field, .structure, "options")
                response.options = try QuickReplyOptionsResponse.read(&reader)
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return response
    }

    func write(to writer: inout ThriftWriter) {
        if let options {
            writer.writeFieldBegin(id: 1, type: .structure)
            options.write(to: &writer)
        }
        writer.writeFieldStop()
    }
}

struct QuickReplyOptionsRequest: Sendable, Equatable {
    var id: String?
    var options: [QuickReplyOption]?

    static func read(_ reader: inout ThriftReader) throws -> QuickReplyOptionsRequest {
        var request = QuickReplyOptionsRequest()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                request.id = try readStringField(field, "id", &reader)
            case 2:
                request.options = try readStructList(field, "options", &reader) {
                    try QuickReplyOption.read(&$0)
                }
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return request
    }

    func write(to writer: inout ThriftWriter) {
        if let id {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(id)
        }
        if let options {
            writer.writeFieldBegin(id: 2, type: .list)
            writer.writeListBegin(elementType: .structure, count: options.count)
            for option in options {
                option.write(to: &writer)
            }
        }
        writer.writeFieldStop()
    }
}

struct QuickReplyOptionsResponse: Sendable, Equatable {
    var requestId: String?
    var metadata: String?
    var selectedOptionId: String?

    static func read(_ reader: inout ThriftReader) throws -> QuickReplyOptionsResponse {
        var response = QuickReplyOptionsResponse()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                response.requestId = try readStringField(field, "request_id", &reader)
            case 2:
                response.metadata = try readStringField(field, "metadata", &reader)
            case 3:
                response.selectedOptionId = try readStringField(
                    field, "selected_option_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return response
    }

    func write(to writer: inout ThriftWriter) {
        if let requestId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(requestId)
        }
        if let metadata {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(metadata)
        }
        if let selectedOptionId {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(selectedOptionId)
        }
        writer.writeFieldStop()
    }
}

struct QuickReplyOption: Sendable, Equatable {
    var id: String?
    var label: String?
    var metadata: String?
    var optionDescription: String?

    static func read(_ reader: inout ThriftReader) throws -> QuickReplyOption {
        var option = QuickReplyOption()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                option.id = try readStringField(field, "id", &reader)
            case 2:
                option.label = try readStringField(field, "label", &reader)
            case 3:
                option.metadata = try readStringField(field, "metadata", &reader)
            case 4:
                option.optionDescription = try readStringField(field, "description", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return option
    }

    func write(to writer: inout ThriftWriter) {
        if let id {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(id)
        }
        if let label {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(label)
        }
        if let metadata {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(metadata)
        }
        if let optionDescription {
            writer.writeFieldBegin(id: 4, type: .binary)
            writer.writeString(optionDescription)
        }
        writer.writeFieldStop()
    }
}

struct CallToAction: Sendable, Equatable {
    var label: String?
    var url: String?

    static func read(_ reader: inout ThriftReader) throws -> CallToAction {
        var callToAction = CallToAction()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                callToAction.label = try readStringField(field, "label", &reader)
            case 2:
                callToAction.url = try readStringField(field, "url", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return callToAction
    }

    func write(to writer: inout ThriftWriter) {
        if let label {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(label)
        }
        if let url {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(url)
        }
        writer.writeFieldStop()
    }
}

/// A reaction added to a message.
struct MessageReactionAdd: Sendable, Equatable {
    var messageSequenceId: String?
    var emoji: String?
    var messageAttachmentId: String?

    static func read(_ reader: inout ThriftReader) throws -> MessageReactionAdd {
        var reaction = MessageReactionAdd()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                reaction.messageSequenceId = try readStringField(
                    field, "message_sequence_id", &reader)
            case 2:
                reaction.emoji = try readStringField(field, "emoji", &reader)
            case 3:
                reaction.messageAttachmentId = try readStringField(
                    field, "message_attachment_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return reaction
    }

    func write(to writer: inout ThriftWriter) {
        if let messageSequenceId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(messageSequenceId)
        }
        if let emoji {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(emoji)
        }
        if let messageAttachmentId {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(messageAttachmentId)
        }
        writer.writeFieldStop()
    }
}

/// A reaction removed from a message.
struct MessageReactionRemove: Sendable, Equatable {
    var messageSequenceId: String?
    var emoji: String?
    var messageAttachmentId: String?

    static func read(_ reader: inout ThriftReader) throws -> MessageReactionRemove {
        var reaction = MessageReactionRemove()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                reaction.messageSequenceId = try readStringField(
                    field, "message_sequence_id", &reader)
            case 2:
                reaction.emoji = try readStringField(field, "emoji", &reader)
            case 3:
                reaction.messageAttachmentId = try readStringField(
                    field, "message_attachment_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return reaction
    }

    func write(to writer: inout ThriftWriter) {
        if let messageSequenceId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(messageSequenceId)
        }
        if let emoji {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(emoji)
        }
        if let messageAttachmentId {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(messageAttachmentId)
        }
        writer.writeFieldStop()
    }
}

/// An edit of a message's text.
struct MessageEdit: Sendable, Equatable {
    var messageSequenceId: String?
    var updatedText: String?
    var entities: [RichTextEntity]?
    var messageId: String?

    static func read(_ reader: inout ThriftReader) throws -> MessageEdit {
        var edit = MessageEdit()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                edit.messageSequenceId = try readStringField(
                    field, "message_sequence_id", &reader)
            case 2:
                edit.updatedText = try readStringField(field, "updated_text", &reader)
            case 3:
                edit.entities = try readStructList(field, "entities", &reader) {
                    try RichTextEntity.read(&$0)
                }
            case 4:
                edit.messageId = try readStringField(field, "message_id", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return edit
    }

    func write(to writer: inout ThriftWriter) {
        if let messageSequenceId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(messageSequenceId)
        }
        if let updatedText {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(updatedText)
        }
        if let entities {
            writer.writeFieldBegin(id: 3, type: .list)
            writer.writeListBegin(elementType: .structure, count: entities.count)
            for entity in entities {
                entity.write(to: &writer)
            }
        }
        if let messageId {
            writer.writeFieldBegin(id: 4, type: .binary)
            writer.writeString(messageId)
        }
        writer.writeFieldStop()
    }
}

/// A read marker for one conversation.
struct MarkConversationRead: Sendable, Equatable {
    var seenUntilSequenceId: String?
    var seenAtMilliseconds: Int64?

    static func read(_ reader: inout ThriftReader) throws -> MarkConversationRead {
        var marker = MarkConversationRead()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                marker.seenUntilSequenceId = try readStringField(
                    field, "seen_until_sequence_id", &reader)
            case 2:
                marker.seenAtMilliseconds = try readI64Field(
                    field, "seen_at_millis", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return marker
    }

    func write(to writer: inout ThriftWriter) {
        if let seenUntilSequenceId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(seenUntilSequenceId)
        }
        if let seenAtMilliseconds {
            writer.writeFieldBegin(id: 2, type: .i64)
            writer.writeI64(seenAtMilliseconds)
        }
        writer.writeFieldStop()
    }
}

/// An unread marker for one conversation.
struct MarkConversationUnread: Sendable, Equatable {
    var seenUntilSequenceId: String?

    static func read(_ reader: inout ThriftReader) throws -> MarkConversationUnread {
        var marker = MarkConversationUnread()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if field.id == 1 {
                marker.seenUntilSequenceId = try readStringField(
                    field, "seen_until_sequence_id", &reader)
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return marker
    }

    func write(to writer: inout ThriftWriter) {
        if let seenUntilSequenceId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(seenUntilSequenceId)
        }
        writer.writeFieldStop()
    }
}
