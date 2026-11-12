import XCTest

@testable import XChat

/// XSalsa20-Poly1305 against NaCl's own `secretbox.c` / `secretbox.out`
/// fixed vector (as adapted into the reference crate's test suite), plus
/// round trips and the message wire format `nonce || tag || ciphertext`.
final class SecretBoxTests: XCTestCase {
    private static func hex(_ string: String) -> [UInt8] {
        try! Hex.decode(string)
    }

    /// NaCl `tests/secretbox.c`: the shared key, nonce, plaintext and the
    /// `secretbox.out` ciphertext (whose first 16 bytes are the tag).
    private static let key = hex(
        "1b27556473e985d462cd51197a9a46c7"
            + "6009549eac6474f206c4ee0844f68389")
    private static let nonce = hex(
        "69696ee955b62b73cd62bda875fc73d6"
            + "8219e0036b7a0b37")
    private static let plaintext = hex(
        "be075fc53c81f2d5cf141316ebeb0c7b"
            + "5228c52a4c62cbd44b66849b64244ffc"
            + "e5ecbaaf33bd751a1ac728d45e6c6129"
            + "6cdc3c01233561f41db66cce314adb31"
            + "0e3be8250c46f06dceea3a7fa1348057"
            + "e2f6556ad6b1318a024a838f21af1fde"
            + "048977eb48f59ffd4924ca1c60902e52"
            + "f0a089bc76897040e082f93776384864"
            + "5e0705")
    private static let ciphertext = hex(
        "f3ffc7703f9400e52a7dfb4b3d3305d9"
            + "8e993b9f48681273c29650ba32fc76ce"
            + "48332ea7164d96a4476fb8c531a1186a"
            + "c0dfc17c98dce87b4da7f011ec48c972"
            + "71d2c20f9b928fe2270d6fb863d51738"
            + "b48eeee314a7cc8ab932164548e526ae"
            + "90224368517acfeabd6bb3732bc0e9da"
            + "99832b61ca01b6de56244a9e88d5f9b3"
            + "7973f622a43d14a6599b1f654cb45a74"
            + "e355a5")

    /// Guards the hand-transcribed vectors against dropped characters.
    func testVectorLengths() {
        XCTAssertEqual(Self.key.count, 32)
        XCTAssertEqual(Self.nonce.count, 24)
        XCTAssertEqual(Self.plaintext.count, 131)
        XCTAssertEqual(Self.ciphertext.count, 147)
    }

    func testNaClSecretboxEncrypt() throws {
        let cipher = XSalsa20Poly1305(key: Self.key)
        let (ciphertext, tag) = try cipher.encryptDetached(nonce: Self.nonce, plaintext: Self.plaintext)
        XCTAssertEqual(tag, Array(Self.ciphertext[0..<16]))
        XCTAssertEqual(ciphertext, Array(Self.ciphertext[16...]))
    }

    func testNaClSecretboxDecrypt() {
        let cipher = XSalsa20Poly1305(key: Self.key)
        let plaintext = try! cipher.decryptDetached(
            nonce: Self.nonce,
            ciphertext: Array(Self.ciphertext[16...]),
            tag: Array(Self.ciphertext[0..<16]))
        XCTAssertEqual(plaintext, Self.plaintext)
    }

    /// The reference crate's `decrypt_modified`: a tweaked ciphertext byte
    /// must fail verification. Every region is covered: ciphertext, tag,
    /// and a keystream-affecting nonce byte.
    func testTamperRejected() throws {
        let cipher = XSalsa20Poly1305(key: Self.key)

        var ct = Array(Self.ciphertext[16...])
        ct[0] ^= 0xaa
        XCTAssertThrowsError(
            try cipher.decryptDetached(nonce: Self.nonce, ciphertext: ct, tag: Array(Self.ciphertext[0..<16])))

        var tag = Array(Self.ciphertext[0..<16])
        tag[15] ^= 1
        XCTAssertThrowsError(
            try cipher.decryptDetached(nonce: Self.nonce, ciphertext: Array(Self.ciphertext[16...]), tag: tag))

        var nonce = Self.nonce
        nonce[0] ^= 1
        XCTAssertThrowsError(
            try cipher.decryptDetached(nonce: nonce, ciphertext: Array(Self.ciphertext[16...]), tag: Array(Self.ciphertext[0..<16])))

        // A wrong-length tag is rejected without touching the ciphertext.
        XCTAssertThrowsError(
            try cipher.decryptDetached(
                nonce: Self.nonce, ciphertext: Array(Self.ciphertext[16...]), tag: Array(Self.ciphertext[0..<15])))
    }

    func testEmptyPlaintext() throws {
        let cipher = XSalsa20Poly1305(key: Self.key)
        let (ciphertext, tag) = try cipher.encryptDetached(nonce: Self.nonce, plaintext: [])
        XCTAssertEqual(ciphertext, [])
        XCTAssertEqual(tag.count, 16)
        let plaintext = try! cipher.decryptDetached(nonce: Self.nonce, ciphertext: ciphertext, tag: tag)
        XCTAssertEqual(plaintext, [])
    }

    /// The NaCl test suite's message-length sweep: every length from 0 to
    /// 1024 round-trips, exercising every Poly1305 padding case.
    func testRoundTripAllLengths0To1024() throws {
        let key = (0..<32).map { UInt8($0 % 256) }
        let nonce = (0..<24).map { UInt8((32 + $0) % 256) }
        let full = (0..<1024).map { UInt8($0 % 256) }
        let cipher = XSalsa20Poly1305(key: key)

        for length in 0...1024 {
            let message = Array(full[0..<length])
            let (ciphertext, tag) = try cipher.encryptDetached(nonce: nonce, plaintext: message)
            XCTAssertEqual(ciphertext.count, length)
            let decrypted = try! cipher.decryptDetached(nonce: nonce, ciphertext: ciphertext, tag: tag)
            XCTAssertEqual(decrypted, message, "length \(length)")
        }
    }

    // MARK: message wire format: nonce (24) || tag (16) || ciphertext

    func testMessageWireRoundTrip() {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let full = (0..<1024).map { UInt8($0 % 256) }

        for length in [0, 1, 16, 40, 131, 1024] {
            let message = Array(full[0..<length])
            let box = try! encryptMessage(key: key, plaintext: message)
            XCTAssertEqual(box.count, 40 + length)
            XCTAssertEqual(Array(box[0..<24]).count, 24)
            let decrypted = try! decryptMessage(key: key, ciphertext: box)
            XCTAssertEqual(decrypted, message, "length \(length)")
        }
    }

    /// A fresh random nonce every call: two encryptions of the same message
    /// differ, and each opens with its own bytes.
    func testMessageWireFreshNonce() {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let message = Array("same message".utf8)

        let first = try! encryptMessage(key: key, plaintext: message)
        let second = try! encryptMessage(key: key, plaintext: message)
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(try! decryptMessage(key: key, ciphertext: first), message)
        XCTAssertEqual(try! decryptMessage(key: key, ciphertext: second), message)
    }

    func testMessageWireTamperRejected() throws {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let message = Array("message to encrypt".utf8)
        let box = try! encryptMessage(key: key, plaintext: message)

        for index in [0, 12, 23, 24, 30, 39, 40, 55] {
            var tampered = box
            tampered[index] ^= 0xff
            XCTAssertThrowsError(try decryptMessage(key: key, ciphertext: tampered), "index \(index)")
        }
    }

    func testMessageWireTooShort() throws {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        for length in [0, 1, 24, 39] {
            let truncated = [UInt8](repeating: 0, count: length)
            XCTAssertThrowsError(try decryptMessage(key: key, ciphertext: truncated)) { error in
                let error = try! XCTUnwrap(error as? XChatError)
                XCTAssertEqual(error.kind, .decryption)
                XCTAssertEqual(error.message, "Ciphertext too short")
            }
        }
    }

    func testMessageWireInvalidKeyLength() throws {
        let shortKey = [UInt8](repeating: 1, count: 16)
        let longKey = [UInt8](repeating: 1, count: 33)
        let message = Array("hi".utf8)
        let box = try! encryptMessage(key: (0..<32).map { _ in UInt8.random(in: 0...255) }, plaintext: message)

        for key in [shortKey, longKey] {
            XCTAssertThrowsError(try encryptMessage(key: key, plaintext: message)) { error in
                let error = try! XCTUnwrap(error as? XChatError)
                XCTAssertEqual(error.kind, .invalidInput)
                XCTAssertEqual(error.message, "Invalid conversation key")
            }
            XCTAssertThrowsError(try decryptMessage(key: key, ciphertext: box)) { error in
                let error = try! XCTUnwrap(error as? XChatError)
                XCTAssertEqual(error.kind, .invalidInput)
                XCTAssertEqual(error.message, "Invalid conversation key")
            }
        }
    }

    func testMessageWireWrongKey() throws {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let otherKey = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let message = Array("message to encrypt".utf8)
        let box = try! encryptMessage(key: key, plaintext: message)

        XCTAssertThrowsError(try decryptMessage(key: otherKey, ciphertext: box)) { error in
            let error = try! XCTUnwrap(error as? XChatError)
            XCTAssertEqual(error.kind, .decryption)
            XCTAssertEqual(error.message, "Decryption failed - invalid key or corrupted data")
        }
    }
}
