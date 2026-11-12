import _Clibsodium

enum SecretStreamTag: UInt8, Sendable {
    case message = 0
    case push = 1
    case rekey = 2
    case final = 3
}

struct SecretStreamPush: Sendable {
    private var state: crypto_secretstream_xchacha20poly1305_state

    static func start(key: [UInt8]) throws -> (header: [UInt8], stream: SecretStreamPush) {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        guard sodiumReady else { throw XChatError.internalError("libsodium initialization failed") }
        var state = crypto_secretstream_xchacha20poly1305_state()
        var header = [UInt8](repeating: 0, count: 24)
        let status = unsafe crypto_secretstream_xchacha20poly1305_init_push(&state, &header, key)
        guard status == 0 else { throw XChatError.internalError("Secretstream initialization failed") }
        return (header, SecretStreamPush(state: state))
    }

    mutating func push(
        _ plaintext: [UInt8], associatedData: [UInt8] = [], tag: SecretStreamTag
    ) throws -> [UInt8] {
        var frame = [UInt8](repeating: 0, count: plaintext.count + 17)
        let status = unsafe crypto_secretstream_xchacha20poly1305_push(
            &state, &frame, nil, plaintext, UInt64(plaintext.count),
            associatedData, UInt64(associatedData.count), tag.rawValue)
        guard status == 0 else { throw XChatError.internalError("Secretstream encryption failed") }
        return frame
    }
}

struct SecretStreamPull: Sendable {
    private var state: crypto_secretstream_xchacha20poly1305_state

    init(header: [UInt8], key: [UInt8]) throws {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        guard header.count == 24 else {
            throw XChatError.invalidInput("secretstream headers are 24 bytes")
        }
        guard sodiumReady else { throw XChatError.internalError("libsodium initialization failed") }
        state = crypto_secretstream_xchacha20poly1305_state()
        let status = unsafe crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key)
        guard status == 0 else { throw XChatError.decryption("Secretstream initialization failed") }
    }

    mutating func pull(
        _ frame: [UInt8], associatedData: [UInt8] = []
    ) throws -> (plaintext: [UInt8], tag: SecretStreamTag) {
        guard frame.count >= 17 else { throw XChatError.decryption("secretstream pull failed") }
        let count = frame.count - 17
        var plaintext = [UInt8](repeating: 0, count: max(1, count))
        var rawTag: UInt8 = 0
        var nextState = state
        let status = unsafe crypto_secretstream_xchacha20poly1305_pull(
            &nextState, &plaintext, nil, &rawTag, frame, UInt64(frame.count),
            associatedData, UInt64(associatedData.count))
        guard status == 0, let tag = SecretStreamTag(rawValue: rawTag) else {
            throw XChatError.decryption("secretstream pull failed")
        }
        state = nextState
        return (Array(plaintext.prefix(count)), tag)
    }
}
