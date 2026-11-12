import XCTest

@testable import Juicebox

/// BLAKE2s against RFC 7693, and the Noise NK client against the official
/// Noise test vectors (`Noise_NK_25519_ChaChaPoly_BLAKE2s`).
final class JuiceboxTests: XCTestCase {
    private static func hex(_ string: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            out.append(UInt8(string[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    func testBlake2sKnownAnswers() {
        XCTAssertEqual(
            Self.hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
            Blake2s.hash(Array("abc".utf8)))
        XCTAssertEqual(
            Self.hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            Blake2s.hash([]))
    }

    /// Each vector fixes the client ephemeral and the server keys, so the
    /// handshake bytes and transport frames are checked exactly.
    func testNoiseNKVectors() throws {
        let vectors = try loadVectors()
        XCTAssertFalse(vectors.isEmpty)

        for (index, vector) in vectors.enumerated() {
            let serverStatic = Self.hex(vector.serverStaticPublic)
            let prologue = Self.hex(vector.prologue)
            let messages = vector.messages
            XCTAssertGreaterThanOrEqual(messages.count, 2, "vector \(index)")

            let (handshake, request) = try NoiseNK.Handshake.start(
                serverStaticPublic: serverStatic,
                prologue: prologue,
                payload: Self.hex(messages[0].payload),
                ephemeralSecret: Self.hex(vector.clientEphemeralSecret))

            // The first message is the client ephemeral followed by the
            // encrypted payload.
            XCTAssertEqual(
                request.clientEphemeralPublic + request.payloadCiphertext,
                Self.hex(messages[0].ciphertext), "vector \(index) message 0")

            let serverMessage = Self.hex(messages[1].ciphertext)
            let response = NoiseNK.HandshakeResponse(
                serverEphemeralPublic: Array(serverMessage[0..<32]),
                payloadCiphertext: Array(serverMessage[32...]))
            var (transport, payload) = try handshake.finish(response)
            XCTAssertEqual(payload, Self.hex(messages[1].payload), "vector \(index) message 1")

            // Messages after the handshake alternate client-to-server and
            // server-to-client, starting with the client.
            var clientSends = true
            for message in messages.dropFirst(2) {
                if clientSends {
                    XCTAssertEqual(
                        try transport.encrypt(Self.hex(message.payload)),
                        Self.hex(message.ciphertext), "vector \(index)")
                } else {
                    XCTAssertEqual(
                        try transport.decrypt(Self.hex(message.ciphertext)),
                        Self.hex(message.payload), "vector \(index)")
                }
                clientSends.toggle()
            }
        }
    }

    // MARK: Fixture

    private struct Vector: Decodable {
        struct Message: Decodable {
            let payload: String
            let ciphertext: String
        }

        let prologue: String
        let clientEphemeralSecret: String
        let serverStaticPublic: String
        let serverEphemeralSecret: String
        let messages: [Message]
    }

    private struct VectorFile: Decodable {
        let vectors: [Vector]
    }

    private func loadVectors() throws -> [Vector] {
        guard
            let url = Bundle.module.url(
                forResource: "noise_nk_vectors", withExtension: "json"),
            let data = try? Data(contentsOf: url)
        else {
            throw XCTSkip("noise_nk_vectors.json is missing from the test bundle")
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(VectorFile.self, from: data).vectors
    }
}
