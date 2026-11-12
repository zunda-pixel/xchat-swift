import Crypto
import XCTest

@testable import XChat

/// ChaCha20 and HChaCha20 against RFC 8439 (§2.3.2, §2.4.2, §2.6.2, §2.8.2,
/// A.4), the XChaCha draft, and swift-crypto's ChaChaPoly, which also
/// cross-checks Poly1305 in AEAD composition.
final class ChaCha20Tests: XCTestCase {
    private func hex(_ string: String) -> [UInt8] {
        try! Hex.decode(string)
    }

    /// XORs `count` zero bytes to expose raw keystream.
    private func keystream(key: [UInt8], nonce: [UInt8], count: Int, seekTo: UInt64? = nil) -> [UInt8] {
        var cipher = ChaCha20(key: key, nonce: nonce)
        if let seekTo { cipher.seek(to: seekTo) }
        var zeros = [UInt8](repeating: 0, count: count)
        cipher.xor(into: &zeros)
        return zeros
    }

    func testRFC8439Section232BlockFunction() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = hex("000000090000004a00000000")
        // Block count 1: seek(to: 64) positions the counter on block 1.
        XCTAssertEqual(
            keystream(key: key, nonce: nonce, count: 64, seekTo: 64),
            hex(
                "10f1e7e4d13b5915500fdd1fa32071c4"
                    + "c7d1f4c733c068030422aa9ac3d46c4e"
                    + "d2826446079faa0914c2d705d98b02a2"
                    + "b5129cd1de164eb9cbd083e8a2503c4e"))
    }

    func testRFC8439Section242Sunscreen() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = hex("000000000000004a00000000")
        // Initial counter 1: seek(to: 64) positions the counter on block 1.
        var cipher = ChaCha20(key: key, nonce: nonce)
        cipher.seek(to: 64)
        var ciphertext = Array(
            ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
                + "the future, sunscreen would be it.").utf8)
        cipher.xor(into: &ciphertext)

        XCTAssertEqual(
            ciphertext,
            hex(
                "6e2e359a2568f98041ba0728dd0d6981"
                    + "e97e7aec1d4360c20a27afccfd9fae0b"
                    + "f91b65c5524733ab8f593dabcd62b357"
                    + "1639d624e65152ab8f530c359f0861d8"
                    + "07ca0dbf500d6a6156a38e088a22b65e"
                    + "52bc514d16ccf806818ce91ab7793736"
                    + "5af90bbf74a35be6b40b8eedf2785e42"
                    + "874d"))
    }

    func testRFC8439Section262PolyKeyGeneration() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = hex("000000000001020304050607")
        XCTAssertEqual(
            keystream(key: key, nonce: nonce, count: 32),
            hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"))
    }

    func testRFC8439AppendixA4PolyKeyGeneration() {
        let vectors: [(key: String, nonce: String, expected: String)] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "000000000000000000000002",
                "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739"
            ),
            (
                "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                "000000000000000000000002",
                "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae"
            ),
        ]
        for vector in vectors {
            XCTAssertEqual(
                keystream(key: hex(vector.key), nonce: hex(vector.nonce), count: 32),
                hex(vector.expected))
        }
    }

    func testHChaCha20DraftVector() {
        XCTAssertEqual(
            hchacha20(
                key: hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                input: hex("000000090000004a0000000031415927")),
            hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"))
    }

    /// RFC 8439 §2.8.2 assembled by hand: ChaCha20 keystream for the one-time
    /// key at counter 0, encryption from counter 1, and a Poly1305 tag over
    /// the §2.8 MAC input.
    func testRFC8439Section282AEADConstruction() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        // The 32-bit fixed-common part precedes the 64-bit IV in the nonce.
        let nonce = hex("070000004041424344454647")
        let aad = hex("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Array(
            ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
                + "the future, sunscreen would be it.").utf8)

        var cipher = ChaCha20(key: key, nonce: nonce)
        var oneTimeKey = [UInt8](repeating: 0, count: 32)
        cipher.xor(into: &oneTimeKey)
        // §2.8: encryption starts with the counter set to 1.
        cipher.seek(to: 64)
        var ciphertext = plaintext
        cipher.xor(into: &ciphertext)

        XCTAssertEqual(
            ciphertext,
            hex(
                "d31a8d34648e60db7b86afbc53ef7ec2"
                    + "a4aded51296e08fea9e2b5a736ee62d6"
                    + "3dbea45e8ca9671282fafb69da92728b"
                    + "1a71de0a9e060b2905d6a5b67ecd3b36"
                    + "92ddbd7f2d778b8c9803aee328091b58"
                    + "fab324e4fad675945585808b4831d7bc"
                    + "3ff4def08e4b7a9de576d26586cec64b"
                    + "6116"))

        var macData = aad
        macData += [UInt8](repeating: 0, count: 16 - aad.count % 16)
        macData += ciphertext
        macData += [UInt8](repeating: 0, count: 16 - ciphertext.count % 16)
        macData += UInt64(aad.count).leBytes
        macData += UInt64(ciphertext.count).leBytes

        var poly = Poly1305(key: oneTimeKey)
        XCTAssertEqual(poly.computeUnpadded(macData), hex("1ae10b594f09e26a7e902ecbd0600691"))
    }

    /// The same §2.8 AEAD construction cross-checked against swift-crypto's
    /// ChaChaPoly at a spread of message and AAD sizes.
    func testChaChaPolyCrossCheckWithSwiftCrypto() {
        for size in [0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 100, 128, 257] {
            for aadSize in [0, 1, 12, 16, 33] {
                let keyBytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
                let nonceBytes = (0..<12).map { _ in UInt8.random(in: 0...255) }
                let plaintext = (0..<size).map { _ in UInt8.random(in: 0...255) }
                let aad = (0..<aadSize).map { _ in UInt8.random(in: 0...255) }

                let sealed = try! ChaChaPoly.seal(
                    plaintext,
                    using: SymmetricKey(data: keyBytes),
                    nonce: ChaChaPoly.Nonce(data: nonceBytes),
                    authenticating: aad)

                var cipher = ChaCha20(key: keyBytes, nonce: nonceBytes)
                var oneTimeKey = [UInt8](repeating: 0, count: 32)
                cipher.xor(into: &oneTimeKey)
                cipher.seek(to: 64)
                var ciphertext = plaintext
                cipher.xor(into: &ciphertext)

                var macData = aad
                if aad.count % 16 != 0 {
                    macData += [UInt8](repeating: 0, count: 16 - aad.count % 16)
                }
                macData += ciphertext
                if ciphertext.count % 16 != 0 {
                    macData += [UInt8](repeating: 0, count: 16 - ciphertext.count % 16)
                }
                macData += UInt64(aad.count).leBytes
                macData += UInt64(ciphertext.count).leBytes

                var poly = Poly1305(key: oneTimeKey)
                XCTAssertEqual(ciphertext, Array(sealed.ciphertext), "ct size \(size) aad \(aadSize)")
                XCTAssertEqual(poly.computeUnpadded(macData), Array(sealed.tag), "tag size \(size) aad \(aadSize)")
            }
        }
    }

    /// Applying the keystream in arbitrary chunks must equal one-shot
    /// application, exercising the buffered partial-block path.
    func testChunkedApplicationMatchesOneShot() {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let nonce = (0..<12).map { _ in UInt8.random(in: 0...255) }
        let data = (0..<300).map { _ in UInt8.random(in: 0...255) }

        var oneShot = data
        var oneShotCipher = ChaCha20(key: key, nonce: nonce)
        oneShotCipher.xor(into: &oneShot)

        var chunked = data
        var chunkedCipher = ChaCha20(key: key, nonce: nonce)
        var offset = 0
        while offset < chunked.count {
            let chunk = Int.random(in: 1...65)
            let end = min(offset + chunk, chunked.count)
            chunkedCipher.xor(into: &chunked, range: offset..<end)
            offset = end
        }

        XCTAssertEqual(chunked, oneShot)
    }

    /// Seeking to any byte offset must equal the matching keystream slice,
    /// including offsets with a block remainder (buffered seek path).
    func testSeekMatchesKeystreamSlice() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = hex("000000000000004a00000000")
        // `full` starts at stream byte 64 (block 1).
        let full = keystream(key: key, nonce: nonce, count: 256, seekTo: 64)

        for offset in [0, 1, 63, 64, 65, 66, 100, 127, 128, 129, 191] {
            let length = 256 - offset
            let slice = keystream(key: key, nonce: nonce, count: length, seekTo: UInt64(64 + offset))
            XCTAssertEqual(Array(full[offset...]), slice, "offset \(offset)")
        }
    }
}
