import XCTest

@testable import XChat

/// `crypto_secretstream_xchacha20poly1305` against the core's cross-binding
/// media vector, plus round trips, rekeying and authentication failures.
final class SecretStreamTests: XCTestCase {
    /// The core's media vector: the conversation key is the raw secretstream
    /// key, so this validates header derivation, frame encryption, MACs and
    /// nonce chaining against ciphertext the Rust core produced.
    private static let key = TestVectors.bytes("conversation_key_b64")
    private static let encrypted = TestVectors.bytes("media_conversation_key_encrypted_b64")
    private static let plaintext = TestVectors.bytes("media_conversation_key_plaintext_b64")

    /// Guards the fixture's shape: a 24-byte header, one full 1041-byte
    /// frame, and a 493-byte final frame for 476 plaintext bytes.
    func testVectorShape() {
        XCTAssertEqual(Self.key.count, 32)
        XCTAssertEqual(Self.plaintext.count, 1500)
        XCTAssertEqual(Self.encrypted.count, 24 + 1041 + 493)
    }

    /// Pulls the vector frame by frame: the first frame is a message and the
    /// last is final.
    func testVectorOpensFrameByFrame() throws {
        var pull = try SecretStreamPull(header: Array(Self.encrypted[0..<24]), key: Self.key)
        var plaintext: [UInt8] = []
        var tags: [SecretStreamTag] = []
        var offset = 24
        while offset < Self.encrypted.count {
            let end = min(offset + 1041, Self.encrypted.count)
            let (message, tag) = try pull.pull(Array(Self.encrypted[offset..<end]))
            plaintext += message
            tags.append(tag)
            offset = end
        }
        XCTAssertEqual(plaintext, Self.plaintext)
        XCTAssertEqual(tags, [.message, .final])
    }

    /// Round trip at every frame boundary and a partial tail.
    func testRoundTripAllLengths() throws {
        let key = (0..<32).map { UInt8(($0 * 7) % 251) }
        let full = (0..<5000).map { UInt8($0 % 251) }

        for length in [0, 1, 15, 16, 17, 63, 64, 65, 1023, 1024, 1025, 2048, 2049] {
            let message = Array(full[0..<length])
            let (header, pusher) = try SecretStreamPush.start(key: key)
            var push = pusher
            let frame = push.push(message, tag: .final)
            XCTAssertEqual(frame.count, 17 + length, "length \(length)")

            var pull = try SecretStreamPull(header: header, key: key)
            let (decrypted, tag) = try pull.pull(frame)
            XCTAssertEqual(decrypted, message, "length \(length)")
            XCTAssertEqual(tag, .final)
        }
    }

    /// A frame with an empty message still carries the tag and its MAC.
    func testEmptyMessage() throws {
        let key = TestVectors.bytes("conversation_key_b64")
        let (header, pusher) = try SecretStreamPush.start(key: key)
        var push = pusher
        let frame = push.push([], tag: .message)
        XCTAssertEqual(frame.count, 17)

        var pull = try SecretStreamPull(header: header, key: key)
        let (decrypted, tag) = try pull.pull(frame)
        XCTAssertEqual(decrypted, [])
        XCTAssertEqual(tag, .message)
    }

    /// Every tag in sequence, including `rekey`, which rotates the key and
    /// nonce on both sides between frames.
    func testEveryTagInSequence() throws {
        let key = TestVectors.bytes("conversation_key_b64")
        let messages: [(SecretStreamTag, [UInt8])] = [
            (.message, Array("first".utf8)),
            (.push, Array("second".utf8)),
            (.rekey, Array("third".utf8)),
            (.message, Array("fourth".utf8)),
            (.rekey, Array("fifth".utf8)),
            (.push, Array("sixth".utf8)),
            (.final, Array("seventh".utf8)),
        ]
        let (header, pusher) = try SecretStreamPush.start(key: key)
        var push = pusher
        var frames: [[UInt8]] = []
        for (tag, message) in messages {
            frames.append(push.push(message, tag: tag))
        }

        var pull = try SecretStreamPull(header: header, key: key)
        for (index, (expectedTag, expectedMessage)) in messages.enumerated() {
            let (message, tag) = try pull.pull(frames[index])
            XCTAssertEqual(tag, expectedTag, "frame \(index)")
            XCTAssertEqual(message, expectedMessage, "frame \(index)")
        }
    }

    /// Associated data is authenticated against the frame, as the reference
    /// test suite's "personal privacy is paramount" example.
    func testAssociatedDataRoundTrip() throws {
        let key = TestVectors.bytes("conversation_key_b64")
        let aad = Array("beware of giving it away".utf8)
        let message = Array("personal privacy is paramount".utf8)

        let (header, pusher) = try SecretStreamPush.start(key: key)
        var push = pusher
        let frame = push.push(message, associatedData: aad, tag: .final)

        var pull = try SecretStreamPull(header: header, key: key)
        let (decrypted, _) = try pull.pull(frame, associatedData: aad)
        XCTAssertEqual(decrypted, message)
    }

    /// The same frame under different associated data must fail
    /// verification and yield no plaintext.
    func testAssociatedDataMismatchRejected() throws {
        let key = TestVectors.bytes("conversation_key_b64")
        let (header, pusher) = try SecretStreamPush.start(key: key)
        var push = pusher
        let frame = push.push([1, 2, 3], associatedData: Array("right".utf8), tag: .final)

        var pull = try SecretStreamPull(header: header, key: key)
        XCTAssertThrowsError(try pull.pull(frame, associatedData: Array("wrong".utf8))) { error in
            let error = error as? XChatError
            XCTAssertEqual(error?.kind, .decryption)
            XCTAssertEqual(error?.message, "secretstream pull failed")
        }
    }

    /// Tampering anywhere — header, tag byte, ciphertext, or MAC — is caught
    /// before any plaintext is produced.
    func testTamperRejected() throws {
        let key = TestVectors.bytes("conversation_key_b64")
        XCTAssertEqual(Self.encrypted.count, 1558)

        // Header byte: changes the derived subkey and nonce.
        var header = Array(Self.encrypted[0..<24])
        header[0] ^= 1
        var pull = try SecretStreamPull(header: header, key: key)
        XCTAssertThrowsError(try pull.pull(Array(Self.encrypted[24..<1065])))

        // Encrypted tag byte, ciphertext body, and MAC of the first frame.
        for index in [24, 25, 100, 1064] {
            var tampered = Self.encrypted
            tampered[index] ^= 0x80
            var framePull = try SecretStreamPull(header: Array(tampered[0..<24]), key: key)
            XCTAssertThrowsError(
                try framePull.pull(Array(tampered[24..<1065])), "byte \(index)")
        }

        // The wrong key fails the same way.
        var wrongKey = key
        wrongKey[31] ^= 1
        var wrongKeyPull = try SecretStreamPull(header: Array(Self.encrypted[0..<24]), key: wrongKey)
        XCTAssertThrowsError(try wrongKeyPull.pull(Array(Self.encrypted[24..<1065])))
    }

    /// A frame shorter than the 17-byte overhead is rejected before any MAC
    /// work, and the stream is not advanced.
    func testShortFrameRejected() throws {
        let key = TestVectors.bytes("conversation_key_b64")
        let header = Array(Self.encrypted[0..<24])
        for length in [0, 1, 16] {
            var pull = try SecretStreamPull(header: header, key: key)
            XCTAssertThrowsError(try pull.pull([UInt8](repeating: 0, count: length))) { error in
                XCTAssertEqual((error as? XChatError)?.kind, .decryption)
            }
        }
    }

    /// Invalid key and header lengths are input errors naming the value.
    func testInvalidLengths() {
        for length in [0, 16, 31, 33] {
            XCTAssertThrowsError(try SecretStreamPush.start(key: [UInt8](repeating: 0, count: length))) {
                error in
                let error = error as? XChatError
                XCTAssertEqual(error?.kind, .invalidInput)
                XCTAssertEqual(error?.message, "Conversation key must be 32 bytes")
            }
            XCTAssertThrowsError(
                try SecretStreamPull(
                    header: [UInt8](repeating: 0, count: 24),
                    key: [UInt8](repeating: 0, count: length))
            ) { error in
                let error = error as? XChatError
                XCTAssertEqual(error?.kind, .invalidInput)
                XCTAssertEqual(error?.message, "Conversation key must be 32 bytes")
            }
        }
        for length in [0, 23, 25] {
            XCTAssertThrowsError(
                try SecretStreamPull(
                    header: [UInt8](repeating: 0, count: length),
                    key: [UInt8](repeating: 0, count: 32))
            ) { error in
                XCTAssertEqual((error as? XChatError)?.message, "secretstream headers are 24 bytes")
            }
        }
    }
}
