/// Event signature versions on the wire, and the payload layouts they sign.
///
/// A signature covers a comma-joined string rebuilt from the event's visible
/// fields; it is never the encoding of the event itself. The layout depends
/// on the version the event's signature carries, so a verifier must rebuild
/// exactly the bytes the signer used.

/// Minimum version accepted on verification. Earlier payloads omit the
/// event-type discriminant and key version, so accepting them would let a
/// forger downgrade to the weaker payload via the attacker-visible field.
let minimumSignatureVersion: Int32 = 2

/// Highest version accepted on verification. A higher version may sign
/// fields this SDK does not know how to reproduce.
let maximumSignatureVersion: Int32 = 11

/// First version whose conversation-key-change payload signs the plaintext
/// conversation key. Earlier versions sign the per-participant key list,
/// which a recipient never receives in full and so cannot reproduce.
let conversationKeyPlaintextSignatureVersion: Int32 = 6

/// First version whose message payload signs `contents_encryption_version`,
/// so the choice of key for the contents is covered by the signature.
let messageSignatureVersion: Int32 = 10

/// Version of v0 sends and signed actions.
let currentSignatureVersion: Int32 = 7

/// A signing key known to the verifier, named by the version its owner
/// published it under.
struct SigningKey: Sendable, Equatable {
    /// Version the key was published as.
    var publicKeyVersion: String
    /// Base64 of the SEC1 signing public key, as other bindings pass it.
    var publicKey: String
}

/// The outcome of checking an event's signature.
enum EventSignatureCheck: Sendable, Equatable {
    /// The signature matched the key at the event's key version.
    case verified
    /// There was nothing to check: no signature, no key at that version, or
    /// no payload layout for the event type.
    case unverifiable
    /// A signature is present but cannot be accepted; the string is why.
    case failed(String)
}

/// The signature version an event carries, when it is an integer.
func signatureVersion(of event: MessageEvent) -> Int32? {
    guard let version = event.messageEventSignature?.signatureVersion else { return nil }
    return Int32(version)
}

/// Renders an optional integer component: digits or `"null"`.
func nullableInt64(_ value: Int64?) -> String {
    value.map(String.init) ?? "null"
}

/// The comma-separated payload an event's signature covers, or nil when the
/// event type is not signed or lacks a field its layout needs.
///
/// `plaintextConversationKeyB64` is the unpadded base64 of the decrypted
/// conversation key bytes, which key-change payloads from v6 on sign.
func eventSignaturePayload(
    event: MessageEvent,
    detail: MessageEventDetail,
    plaintextConversationKeyB64: String? = nil
) -> String? {
    guard let messageId = event.messageId, let senderId = event.senderId,
        let version = signatureVersion(of: event)
    else { return nil }
    let conversationId = event.conversationId

    guard
        let payload = componentPayloadForDetail(
            detail: detail, version: version, messageId: messageId, senderId: senderId,
            conversationId: conversationId,
            plaintextConversationKeyB64: plaintextConversationKeyB64)
    else { return nil }

    // v9+ binds the signature version into every component payload.
    if version >= 9 {
        return payload + ",signature_version=\(version)"
    }
    return payload
}

private func componentPayloadForDetail(
    detail: MessageEventDetail,
    version: Int32,
    messageId: String,
    senderId: String,
    conversationId: String?,
    plaintextConversationKeyB64: String?
) -> String? {
    switch detail {
    case .messageCreate(let create):
        guard version >= minimumSignatureVersion, let contents = create.contents else {
            return nil
        }
        let keyVersion = nullableInt64(
            create.conversationKeyVersion.flatMap { Int64($0) })
        var extra = [keyVersion, Base64.encodeStandard(contents)]
        if version >= messageSignatureVersion {
            extra.append(nullableInt64(create.contentsEncryptionVersion.map { Int64($0) }))
        }
        return componentPayload(
            "MessageCreateEvent", messageId, senderId, conversationId, extra)

    case .conversationKeyChange(let change):
        // The key version signs as its integer value; a key change without
        // one has no payload.
        guard let versionString = change.conversationKeyVersion,
            let keyVersion = Int64(versionString)
        else { return nil }

        if version >= conversationKeyPlaintextSignatureVersion {
            guard let keyB64 = plaintextConversationKeyB64 else { return nil }
            return componentPayload(
                "ConversationKeyChangeEvent", messageId, senderId, conversationId,
                [String(keyVersion), keyB64])
        }
        // Before v6 the payload signs each participant's encrypted key
        // triplet, leaving out the fields an entry lacks.
        guard let keys = change.conversationParticipantKeys else { return nil }
        var extra = [String(keyVersion)]
        for key in keys {
            if let userId = key.userId { extra.append(userId) }
            if let encrypted = key.encryptedConversationKey { extra.append(encrypted) }
            if let keyVersionName = key.publicKeyVersion { extra.append(keyVersionName) }
        }
        return componentPayload(
            "ConversationKeyChangeEvent", messageId, senderId, conversationId, extra)

    case .messageDelete(let deletion):
        guard let action = deletion.deleteMessageAction, let sequenceIds = deletion.sequenceIds
        else { return nil }
        return componentPayload(
            "MessageDeleteEvent", messageId, senderId, conversationId,
            [String(action)] + sequenceIds)

    case .conversationDelete:
        return componentPayload(
            "ConversationDeleteEvent", messageId, senderId, conversationId, [])

    // Typing and failure events carry no signature; unmodelled variants
    // (group and conversation-metadata changes, read markers, …) have
    // layouts this SDK does not rebuild.
    case .messageTyping, .messageFailure, .unsupported:
        return nil
    }
}

/// Joins the payload components, rejecting any that contains a comma: the
/// payload has no escaping, so an embedded comma would make one signed byte
/// string decode as two different component sequences.
private func componentPayload(
    _ eventName: String,
    _ messageId: String,
    _ senderId: String,
    _ conversationId: String?,
    _ additional: [String]
) -> String? {
    var parts = [eventName, messageId, senderId]
    if let conversationId { parts.append(conversationId) }
    parts.append(contentsOf: additional)
    if parts.contains(where: { $0.contains(",") }) { return nil }
    return parts.joined(separator: ",")
}

/// Checks an event's signature against the known signing keys.
///
/// The key is chosen by the `public_key_version` the event's signature
/// names; the payload is rebuilt from the event in its signature version's
/// layout, so a signature the reference produced verifies here without any
/// other state.
func checkEventSignature(
    event: MessageEvent,
    detail: MessageEventDetail,
    signingKeys: [SigningKey],
    plaintextConversationKeyB64: String? = nil
) -> EventSignatureCheck {
    guard let signature = event.messageEventSignature,
        let signatureB64 = signature.signature
    else { return .unverifiable }

    guard let version = signatureVersion(of: event) else {
        return .failed("signature_version is missing or not an integer")
    }
    guard version >= minimumSignatureVersion else {
        return .failed(
            "signature_version \(version) is no longer accepted "
                + "(minimum: \(minimumSignatureVersion))")
    }
    guard version <= maximumSignatureVersion else {
        return .failed(
            "signature_version \(version) is not supported "
                + "(maximum: \(maximumSignatureVersion))")
    }

    let keyVersion = signature.publicKeyVersion ?? ""
    guard let entry = signingKeys.first(where: { $0.publicKeyVersion == keyVersion }) else {
        return .unverifiable
    }
    guard
        let payload = eventSignaturePayload(
            event: event, detail: detail,
            plaintextConversationKeyB64: plaintextConversationKeyB64)
    else { return .unverifiable }

    do {
        let publicKey = try Base64.decodeStandard(entry.publicKey)
        let signatureBytes = (try? Base64.decodeStandard(signatureB64)) ?? []
        if try verify(
            publicKey: publicKey, signature: signatureBytes, payload: Array(payload.utf8))
        {
            return .verified
        }
        return .failed(
            "ECDSA mismatch: key_version=\(keyVersion), payload_len=\(payload.utf8.count)")
    } catch {
        let reason = (error as? XChatError)?.message ?? String(describing: error)
        return .failed("verify error: \(reason)")
    }
}

/// Signs an event's payload at `signatureVersion`, returning the signature
/// struct the event carries and the payload that was signed.
func signEventSignature(
    signingPrivateKey: [UInt8],
    publicKeyVersion: String,
    messageId: String,
    senderId: String,
    conversationId: String?,
    signatureVersion: Int32,
    detail: MessageEventDetail,
    plaintextConversationKeyB64: String? = nil
) throws -> (signature: MessageEventSignature, payload: String) {
    var event = MessageEvent()
    event.messageId = messageId
    event.senderId = senderId
    event.conversationId = conversationId
    var signatureFields = MessageEventSignature()
    signatureFields.signatureVersion = String(signatureVersion)
    event.messageEventSignature = signatureFields

    guard
        let payload = eventSignaturePayload(
            event: event, detail: detail,
            plaintextConversationKeyB64: plaintextConversationKeyB64)
    else {
        throw XChatError.invalidInput("Signature payload contains comma-separated component")
    }

    let signature = try sign(privateKey: signingPrivateKey, payload: Array(payload.utf8))
    let publicKey = try derivePublicKey(privateKey: signingPrivateKey)
    let signatureStruct = MessageEventSignature(
        signature: Base64.encodeStandard(signature),
        publicKeyVersion: publicKeyVersion,
        signatureVersion: String(signatureVersion),
        signingPublicKey: Base64.encodeStandard(publicKey),
        messageSigningKeyInfoList: nil)
    return (signatureStruct, payload)
}
