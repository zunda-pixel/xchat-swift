/// The event envelope the server relays: one `MessageEvent` per relayed
/// event, carrying the visible metadata and a `MessageEventDetail` variant.
struct MessageEvent: Sendable, Equatable {
    var sequenceId: String?
    var messageId: String?
    var senderId: String?
    var conversationId: String?
    var conversationToken: String?
    var createdAtMilliseconds: String?
    var detail: MessageEventDetail?
    var relaySource: Int32?
    var messageEventSignature: MessageEventSignature?
    var previousSequenceId: String?
    var isTrusted: Bool?
    var conversationEventCounter: String?

    static func read(_ reader: inout ThriftReader) throws -> MessageEvent {
        var event = MessageEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                event.sequenceId = try readStringField(field, "sequence_id", &reader)
            case 2:
                event.messageId = try readStringField(field, "message_id", &reader)
            case 3:
                event.senderId = try readStringField(field, "sender_id", &reader)
            case 4:
                event.conversationId = try readStringField(field, "conversation_id", &reader)
            case 5:
                event.conversationToken = try readStringField(field, "conversation_token", &reader)
            case 6:
                event.createdAtMilliseconds = try readStringField(
                    field, "created_at_msec", &reader)
            case 7:
                try expectField(field, .structure, "detail")
                event.detail = try MessageEventDetail.read(&reader)
            case 8:
                event.relaySource = try readI32Field(field, "relay_source", &reader)
            case 9:
                try expectField(field, .structure, "message_event_signature")
                event.messageEventSignature = try MessageEventSignature.read(&reader)
            case 10:
                event.previousSequenceId = try readStringField(
                    field, "previous_sequence_id", &reader)
            case 11:
                event.isTrusted = try readBoolField(field, "is_trusted", &reader)
            case 13:
                event.conversationEventCounter = try readStringField(
                    field, "conversation_event_counter", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let sequenceId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(sequenceId)
        }
        if let messageId {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(messageId)
        }
        if let senderId {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(senderId)
        }
        if let conversationId {
            writer.writeFieldBegin(id: 4, type: .binary)
            writer.writeString(conversationId)
        }
        if let conversationToken {
            writer.writeFieldBegin(id: 5, type: .binary)
            writer.writeString(conversationToken)
        }
        if let createdAtMilliseconds {
            writer.writeFieldBegin(id: 6, type: .binary)
            writer.writeString(createdAtMilliseconds)
        }
        if let detail {
            writer.writeFieldBegin(id: 7, type: .structure)
            detail.write(to: &writer)
        }
        if let relaySource {
            writer.writeFieldBegin(id: 8, type: .i32)
            writer.writeI32(relaySource)
        }
        if let messageEventSignature {
            writer.writeFieldBegin(id: 9, type: .structure)
            messageEventSignature.write(to: &writer)
        }
        if let previousSequenceId {
            writer.writeFieldBegin(id: 10, type: .binary)
            writer.writeString(previousSequenceId)
        }
        if let isTrusted {
            writer.writeFieldBegin(id: 11, type: .bool)
            writer.writeBool(isTrusted)
        }
        if let conversationEventCounter {
            writer.writeFieldBegin(id: 13, type: .binary)
            writer.writeString(conversationEventCounter)
        }
        writer.writeFieldStop()
    }
}

/// The signed payload of an event: the signature covers bytes rebuilt from
/// the event fields, not this struct's encoding.
struct MessageEventSignature: Sendable, Equatable {
    var signature: String?
    var publicKeyVersion: String?
    var signatureVersion: String?
    var signingPublicKey: String?
    var messageSigningKeyInfoList: [MessageSigningKeyInfo]?

    static func read(_ reader: inout ThriftReader) throws -> MessageEventSignature {
        var signature = MessageEventSignature()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                signature.signature = try readStringField(field, "signature", &reader)
            case 2:
                signature.publicKeyVersion = try readStringField(
                    field, "public_key_version", &reader)
            case 3:
                signature.signatureVersion = try readStringField(
                    field, "signature_version", &reader)
            case 4:
                signature.signingPublicKey = try readStringField(
                    field, "signing_public_key", &reader)
            case 5:
                signature.messageSigningKeyInfoList = try readStructList(
                    field, "message_signing_key_info_list", &reader) {
                        try MessageSigningKeyInfo.read(&$0)
                    }
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return signature
    }

    func write(to writer: inout ThriftWriter) {
        if let signature {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(signature)
        }
        if let publicKeyVersion {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(publicKeyVersion)
        }
        if let signatureVersion {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(signatureVersion)
        }
        if let signingPublicKey {
            writer.writeFieldBegin(id: 4, type: .binary)
            writer.writeString(signingPublicKey)
        }
        if let messageSigningKeyInfoList {
            writer.writeFieldBegin(id: 5, type: .list)
            writer.writeListBegin(elementType: .structure, count: messageSigningKeyInfoList.count)
            for info in messageSigningKeyInfoList {
                info.write(to: &writer)
            }
        }
        writer.writeFieldStop()
    }
}

/// A signing key a multi-user event was signed with.
struct MessageSigningKeyInfo: Sendable, Equatable {
    var memberId: String?
    var publicKeyVersion: String?
    var signingPublicKey: String?

    static func read(_ reader: inout ThriftReader) throws -> MessageSigningKeyInfo {
        var info = MessageSigningKeyInfo()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                info.memberId = try readStringField(field, "member_id", &reader)
            case 2:
                info.publicKeyVersion = try readStringField(field, "public_key_version", &reader)
            case 3:
                info.signingPublicKey = try readStringField(
                    field, "signing_public_key", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return info
    }

    func write(to writer: inout ThriftWriter) {
        if let memberId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(memberId)
        }
        if let publicKeyVersion {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(publicKeyVersion)
        }
        if let signingPublicKey {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(signingPublicKey)
        }
        writer.writeFieldStop()
    }
}

/// The event variant a `MessageEvent` carries.
enum MessageEventDetail: Sendable, Equatable {
    case messageCreate(MessageCreateEvent)
    case conversationKeyChange(ConversationKeyChangeEvent)
    case messageFailure(MessageFailureEvent)
    case messageTyping(MessageTypingEvent)
    case messageDelete(MessageDeleteEvent)
    case conversationDelete(ConversationDeleteEvent)
    /// A variant this SDK does not model (group and conversation-metadata
    /// changes, pins, Grok, …), identified by its union field id.
    case unsupported(fieldId: Int16)

    static func read(_ reader: inout ThriftReader) throws -> MessageEventDetail? {
        var detail: MessageEventDetail?
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            if detail == nil {
                switch field.id {
                case 1:
                    try expectField(field, .structure, "messageCreateEvent")
                    detail = .messageCreate(try MessageCreateEvent.read(&reader))
                case 3:
                    try expectField(field, .structure, "conversationKeyChangeEvent")
                    detail = .conversationKeyChange(
                        try ConversationKeyChangeEvent.read(&reader))
                case 5:
                    try expectField(field, .structure, "messageFailureEvent")
                    detail = .messageFailure(try MessageFailureEvent.read(&reader))
                case 6:
                    try expectField(field, .structure, "messageTypingEvent")
                    detail = .messageTyping(try MessageTypingEvent.read(&reader))
                case 7:
                    try expectField(field, .structure, "messageDeleteEvent")
                    detail = .messageDelete(try MessageDeleteEvent.read(&reader))
                case 8:
                    try expectField(field, .structure, "conversationDeleteEvent")
                    detail = .conversationDelete(try ConversationDeleteEvent.read(&reader))
                default:
                    detail = .unsupported(fieldId: field.id)
                    try reader.skip(field.type)
                }
            } else {
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return detail
    }

    func write(to writer: inout ThriftWriter) {
        switch self {
        case .messageCreate(let event):
            writer.writeFieldBegin(id: 1, type: .structure)
            event.write(to: &writer)
        case .conversationKeyChange(let event):
            writer.writeFieldBegin(id: 3, type: .structure)
            event.write(to: &writer)
        case .messageFailure(let event):
            writer.writeFieldBegin(id: 5, type: .structure)
            event.write(to: &writer)
        case .messageTyping(let event):
            writer.writeFieldBegin(id: 6, type: .structure)
            event.write(to: &writer)
        case .messageDelete(let event):
            writer.writeFieldBegin(id: 7, type: .structure)
            event.write(to: &writer)
        case .conversationDelete(let event):
            writer.writeFieldBegin(id: 8, type: .structure)
            event.write(to: &writer)
        case .unsupported:
            // Read-only: a variant this SDK cannot write.
            break
        }
        writer.writeFieldStop()
    }
}

/// A message's encrypted contents and the metadata the server relays.
struct MessageCreateEvent: Sendable, Equatable {
    var contents: [UInt8]?
    var conversationKeyVersion: String?
    var shouldNotify: Bool?
    var ttlMilliseconds: Int64?
    var deliveredAtMilliseconds: Int64?
    var isPendingPublicKey: Bool?
    var isMessageRequest: Bool?
    var contentsEncryptionVersion: Int16?

    static func read(_ reader: inout ThriftReader) throws -> MessageCreateEvent {
        var event = MessageCreateEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 100:
                event.contents = try readBinaryField(field, "contents", &reader)
            case 101:
                event.conversationKeyVersion = try readStringField(
                    field, "conversation_key_version", &reader)
            case 102:
                event.shouldNotify = try readBoolField(field, "should_notify", &reader)
            case 103:
                event.ttlMilliseconds = try readI64Field(field, "ttl_msec", &reader)
            case 104:
                event.deliveredAtMilliseconds = try readI64Field(
                    field, "delivered_at_msec", &reader)
            case 105:
                event.isPendingPublicKey = try readBoolField(
                    field, "is_pending_public_key", &reader)
            case 109:
                event.isMessageRequest = try readBoolField(
                    field, "is_message_request", &reader)
            case 112:
                event.contentsEncryptionVersion = try readI16Field(
                    field, "contents_encryption_version", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let contents {
            writer.writeFieldBegin(id: 100, type: .binary)
            writer.writeBinary(contents)
        }
        if let conversationKeyVersion {
            writer.writeFieldBegin(id: 101, type: .binary)
            writer.writeString(conversationKeyVersion)
        }
        if let shouldNotify {
            writer.writeFieldBegin(id: 102, type: .bool)
            writer.writeBool(shouldNotify)
        }
        if let ttlMilliseconds {
            writer.writeFieldBegin(id: 103, type: .i64)
            writer.writeI64(ttlMilliseconds)
        }
        if let deliveredAtMilliseconds {
            writer.writeFieldBegin(id: 104, type: .i64)
            writer.writeI64(deliveredAtMilliseconds)
        }
        if let isPendingPublicKey {
            writer.writeFieldBegin(id: 105, type: .bool)
            writer.writeBool(isPendingPublicKey)
        }
        if let isMessageRequest {
            writer.writeFieldBegin(id: 109, type: .bool)
            writer.writeBool(isMessageRequest)
        }
        if let contentsEncryptionVersion {
            writer.writeFieldBegin(id: 112, type: .i16)
            writer.writeI16(contentsEncryptionVersion)
        }
        writer.writeFieldStop()
    }
}

/// A conversation key change: the new key version and its per-participant
/// ECIES-encrypted copies.
struct ConversationKeyChangeEvent: Sendable, Equatable {
    var conversationKeyVersion: String?
    var conversationParticipantKeys: [ConversationParticipantKey]?
    var forKeyRotation: Bool?

    static func read(_ reader: inout ThriftReader) throws -> ConversationKeyChangeEvent {
        var event = ConversationKeyChangeEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                event.conversationKeyVersion = try readStringField(
                    field, "conversation_key_version", &reader)
            case 2:
                event.conversationParticipantKeys = try readStructList(
                    field, "conversation_participant_keys", &reader) {
                        try ConversationParticipantKey.read(&$0)
                    }
            case 5:
                event.forKeyRotation = try readBoolField(field, "for_key_rotation", &reader)
            default:
                // Field 4 is the group ratchet-tree change, which this SDK
                // does not model.
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let conversationKeyVersion {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(conversationKeyVersion)
        }
        if let conversationParticipantKeys {
            writer.writeFieldBegin(id: 2, type: .list)
            writer.writeListBegin(
                elementType: .structure, count: conversationParticipantKeys.count)
            for key in conversationParticipantKeys {
                key.write(to: &writer)
            }
        }
        if let forKeyRotation {
            writer.writeFieldBegin(id: 5, type: .bool)
            writer.writeBool(forKeyRotation)
        }
        writer.writeFieldStop()
    }
}

/// One participant's copy of a conversation-key change, ECIES-encrypted to
/// that participant's identity key.
struct ConversationParticipantKey: Sendable, Equatable {
    var userId: String?
    var encryptedConversationKey: String?
    var publicKeyVersion: String?

    static func read(_ reader: inout ThriftReader) throws -> ConversationParticipantKey {
        var key = ConversationParticipantKey()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                key.userId = try readStringField(field, "user_id", &reader)
            case 2:
                key.encryptedConversationKey = try readStringField(
                    field, "encrypted_conversation_key", &reader)
            case 3:
                key.publicKeyVersion = try readStringField(
                    field, "public_key_version", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return key
    }

    func write(to writer: inout ThriftWriter) {
        if let userId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(userId)
        }
        if let encryptedConversationKey {
            writer.writeFieldBegin(id: 2, type: .binary)
            writer.writeString(encryptedConversationKey)
        }
        if let publicKeyVersion {
            writer.writeFieldBegin(id: 3, type: .binary)
            writer.writeString(publicKeyVersion)
        }
        writer.writeFieldStop()
    }
}

/// Why the backend refused a message.
struct MessageFailureEvent: Sendable, Equatable {
    var failureType: Int32?
    var rateLimitTier: Int32?

    static func read(_ reader: inout ThriftReader) throws -> MessageFailureEvent {
        var event = MessageFailureEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                event.failureType = try readI32Field(field, "failure_type", &reader)
            case 2:
                event.rateLimitTier = try readI32Field(field, "rate_limit_tier", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let failureType {
            writer.writeFieldBegin(id: 1, type: .i32)
            writer.writeI32(failureType)
        }
        if let rateLimitTier {
            writer.writeFieldBegin(id: 2, type: .i32)
            writer.writeI32(rateLimitTier)
        }
        writer.writeFieldStop()
    }
}

/// Someone typing or recording in a conversation.
struct MessageTypingEvent: Sendable, Equatable {
    var conversationId: String?
    var activityType: Int32?
    var isGrok: Bool?
    var createdAtMilliseconds: String?

    static func read(_ reader: inout ThriftReader) throws -> MessageTypingEvent {
        var event = MessageTypingEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                event.conversationId = try readStringField(field, "conversation_id", &reader)
            case 2:
                event.activityType = try readI32Field(field, "activity_type", &reader)
            case 3:
                event.isGrok = try readBoolField(field, "is_grok", &reader)
            case 4:
                event.createdAtMilliseconds = try readStringField(
                    field, "created_at_msec", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let conversationId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(conversationId)
        }
        if let activityType {
            writer.writeFieldBegin(id: 2, type: .i32)
            writer.writeI32(activityType)
        }
        if let isGrok {
            writer.writeFieldBegin(id: 3, type: .bool)
            writer.writeBool(isGrok)
        }
        if let createdAtMilliseconds {
            writer.writeFieldBegin(id: 4, type: .binary)
            writer.writeString(createdAtMilliseconds)
        }
        writer.writeFieldStop()
    }
}

/// A tombstone naming the messages it deletes.
struct MessageDeleteEvent: Sendable, Equatable {
    var sequenceIds: [String]?
    var deleteMessageAction: Int32?
    var pinnedMessageSequenceIds: [String: String]?

    static func read(_ reader: inout ThriftReader) throws -> MessageDeleteEvent {
        var event = MessageDeleteEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                event.sequenceIds = try readStringList(field, "sequence_ids", &reader)
            case 2:
                event.deleteMessageAction = try readI32Field(
                    field, "delete_message_action", &reader)
            case 3:
                event.pinnedMessageSequenceIds = try readStringMap(
                    field, "pme_sequence_ids", &reader)
            default:
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let sequenceIds {
            writer.writeFieldBegin(id: 1, type: .list)
            writer.writeListBegin(elementType: .binary, count: sequenceIds.count)
            for id in sequenceIds {
                writer.writeString(id)
            }
        }
        if let deleteMessageAction {
            writer.writeFieldBegin(id: 2, type: .i32)
            writer.writeI32(deleteMessageAction)
        }
        if let pinnedMessageSequenceIds {
            writer.writeFieldBegin(id: 3, type: .map)
            writer.writeMapBegin(
                keyType: .binary, valueType: .binary, count: pinnedMessageSequenceIds.count)
            for (key, value) in pinnedMessageSequenceIds {
                writer.writeString(key)
                writer.writeString(value)
            }
        }
        writer.writeFieldStop()
    }
}

/// A whole conversation erased, optionally with its local message store.
struct ConversationDeleteEvent: Sendable, Equatable {
    var conversationId: String?

    static func read(_ reader: inout ThriftReader) throws -> ConversationDeleteEvent {
        var event = ConversationDeleteEvent()
        var field = try reader.readFieldBegin()
        while field.type != .stop {
            switch field.id {
            case 1:
                event.conversationId = try readStringField(field, "conversation_id", &reader)
            default:
                // Field 2 carries the clear-history options, which this SDK
                // does not model.
                try reader.skip(field.type)
            }
            field = try reader.readFieldBegin()
        }
        return event
    }

    func write(to writer: inout ThriftWriter) {
        if let conversationId {
            writer.writeFieldBegin(id: 1, type: .binary)
            writer.writeString(conversationId)
        }
        writer.writeFieldStop()
    }
}
