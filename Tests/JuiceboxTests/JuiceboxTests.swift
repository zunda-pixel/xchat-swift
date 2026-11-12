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

    private static func hexString(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var chars: [UInt8] = []
        for byte in bytes {
            chars.append(digits[Int(byte >> 4)])
            chars.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: chars, as: UTF8.self)
    }

    func testBlake2sKnownAnswers() {
        XCTAssertEqual(
            Self.hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
            Blake2s.hash(Array("abc".utf8)))
        XCTAssertEqual(
            Self.hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            Blake2s.hash([]))
    }

    func testBlake2bKnownAnswers() {
        XCTAssertEqual(
            Self.hex(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                    + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
            Blake2b.hash(Array("abc".utf8)))
        XCTAssertEqual(
            Self.hex(
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                    + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
            Blake2b.hash([]))
    }

    /// RFC 9106's Argon2id vector, with the secret and associated data the
    /// standard's test cases use.
    func testArgon2idRFC9106Vector() {
        let tag = Argon2.id(
            password: [UInt8](repeating: 0x01, count: 32),
            salt: [UInt8](repeating: 0x02, count: 16),
            secret: [UInt8](repeating: 0x03, count: 8),
            associatedData: [UInt8](repeating: 0x04, count: 12),
            memoryCost: 32, timeCost: 3, parallelism: 4,
            outputLength: 32)
        XCTAssertEqual(
            Self.hexString(tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    }

    /// The reference implementation's PIN vector (`pin.rs`): PIN "1234",
    /// registration version `[5; 16]`, user info "artemis".
    func testJuiceboxPinHashVector() {
        let (accessKey, seed) = juiceboxPinHash(
            pin: Array("1234".utf8),
            registrationVersion: [UInt8](repeating: 5, count: 16),
            userInfo: Array("artemis".utf8))
        XCTAssertEqual(
            Self.hexString(accessKey),
            "2935da84c97423b37f3457231b877ce6ac2093501d7255dbee1deb09a5d8821b")
        XCTAssertEqual(
            Self.hexString(seed),
            "87c8c9b5d3ea9fea83b6ac6a64e25b97c4722ca4e40bea2523efea262125e22a")
    }

    // MARK: Field arithmetic

    /// Values computed with plain integer arithmetic modulo 2^255 - 19,
    /// independent of this implementation.
    func testFieldElement51Arithmetic() {
        let a = FieldElement51.fromBytes(Self.hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
        let b = FieldElement51.fromBytes(Self.hex(
            "160a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced55c"))

        XCTAssertEqual(
            Self.hexString((a + b).asBytes()),
            "170c141c242c343c444c545c646c747c848c949ca4acb4bcc4ccd4dce4ecf47c")
        XCTAssertEqual(
            Self.hexString((a - b).asBytes()),
            "d8f7f1ebe5dfd9d3cdc7c1bbb5afa9a39d97918b857f79736d67615b554f4943")
        XCTAssertEqual(
            Self.hexString((a * b).asBytes()),
            "f19a06974714f9f1fa0f2d4e6f8ca1aaa38855069703486048fc77b7b671e40a")
        XCTAssertEqual(
            Self.hexString(a.square().asBytes()),
            "4bf177a55460a3f83a45f21ca0561bc93a4bd5b3c1d9d693ebb8d61f6f9f8b0e")
        XCTAssertEqual(
            Self.hexString(a.invert().asBytes()),
            "e5faf5a435158b4cc68d583058fece071d8b8d20ed6abf17651a73c28fec414d")
        XCTAssertEqual(
            Self.hexString((-a).asBytes()),
            "ecfdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e05f")
        XCTAssertEqual(
            Self.hexString((a * a.invert()).asBytes()),
            Self.hexString([1] + [UInt8](repeating: 0, count: 31)))

        // 2^255 - 18 is congruent to 1 and must encode canonically.
        var nonCanonical = [UInt8](repeating: 0xff, count: 32)
        nonCanonical[0] = 0xee
        nonCanonical[31] = 0x7f
        XCTAssertEqual(
            Self.hexString(FieldElement51.fromBytes(nonCanonical).asBytes()),
            "0100000000000000000000000000000000000000000000000000000000000000")

        // sqrt(-1)^2 = -1.
        XCTAssertEqual(
            Self.hexString((FieldElement51.sqrtM1 * FieldElement51.sqrtM1).asBytes()),
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    }

    /// `sqrtRatioI` returns the nonnegative root, and the square flag says
    /// whether `u/v` or `i*u/v` was taken.
    func testFieldElement51SqrtRatioI() {
        let four = FieldElement51.fromBytes(Self.hex(
            "0400000000000000000000000000000000000000000000000000000000000000"))
        let nine = FieldElement51.fromBytes(Self.hex(
            "0900000000000000000000000000000000000000000000000000000000000000"))
        let two = FieldElement51.fromBytes(Self.hex(
            "0200000000000000000000000000000000000000000000000000000000000000"))
        let one = FieldElement51.one

        let (square, squareRoot) = FieldElement51.sqrtRatioI(four, nine)
        XCTAssertTrue(square.boolValue)
        XCTAssertEqual(
            Self.hexString(squareRoot.asBytes()),
            "4855555555555555555555555555555555555555555555555555555555555555")
        XCTAssertEqual(squareRoot.square() * nine, four)

        // 2 is not a square, so this is sqrt(i*2).
        let (nonsquare, imaginaryRoot) = FieldElement51.sqrtRatioI(two, one)
        XCTAssertFalse(nonsquare.boolValue)
        XCTAssertEqual(
            Self.hexString(imaginaryRoot.asBytes()),
            "3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54")
        XCTAssertEqual(imaginaryRoot.square(), FieldElement51.sqrtM1 * two)

        XCTAssertTrue(FieldElement51.sqrtRatioI(.zero, one).0.boolValue)
        XCTAssertFalse(FieldElement51.sqrtRatioI(one, .zero).0.boolValue)
    }

    // MARK: Scalar

    /// The reference implementation's own `Scalar52` test vectors, which
    /// exercise the limb arithmetic directly.
    func testScalar52ReferenceVectors() {
        let x = Scalar52([
            0x000f_ffff_ffff_ffff, 0x000f_ffff_ffff_ffff, 0x000f_ffff_ffff_ffff,
            0x000f_ffff_ffff_ffff, 0x0000_1fff_ffff_ffff,
        ])
        let y = Scalar52([
            0x000b_7507_1e14_58fa, 0x000b_f9d7_5e1e_cdac, 0x0004_33d2_baf0_672b,
            0x0005_fffc_c11f_ad13, 0x0000_0d96_018b_b825,
        ])
        let a = Scalar52([
            0x0005_236c_07b3_be89, 0x0001_bc3d_2a67_c0c4, 0x000a_4aa7_82aa_e3ee,
            0x0006_b3f6_e4fe_c4c4, 0x0000_0532_da9f_ab8c,
        ])
        let b = Scalar52([
            0x000d_3fae_5542_1564, 0x000c_2df2_4f65_a4bc, 0x0005_b558_7d69_fb0b,
            0x0009_4c09_1b01_3b3b, 0x0000_0acd_2560_5473,
        ])

        // x^2
        XCTAssertEqual(
            Scalar52.mul(x, x),
            Scalar52([
                0x0001_6680_2021_7559, 0x0005_3164_0ffd_0ec0, 0x0008_5fd6_f9f3_8a31,
                0x000c_268f_73bb_1cf4, 0x0000_06ce_6504_6df0,
            ]))
        XCTAssertEqual(
            x.square(),
            Scalar52([
                0x0001_6680_2021_7559, 0x0005_3164_0ffd_0ec0, 0x0008_5fd6_f9f3_8a31,
                0x000c_268f_73bb_1cf4, 0x0000_06ce_6504_6df0,
            ]))

        // x * y
        XCTAssertEqual(
            Scalar52.mul(x, y),
            Scalar52([
                0x000e_e6d7_6ba7_632d, 0x000e_d50d_71d8_4e02, 0x0000_0000_001b_a634,
                0x0000_0000_0000_0000, 0x0000_0000_0000_0000,
            ]))

        // Montgomery products
        XCTAssertEqual(
            Scalar52.montgomeryMul(x, x),
            Scalar52([
                0x000c_754e_ea56_9a5c, 0x0006_3b6e_d36c_b215, 0x0008_ffa3_6bf2_5886,
                0x000e_9183_614e_7543, 0x0000_061d_b6c6_f26f,
            ]))
        XCTAssertEqual(
            Scalar52.montgomeryMul(x, y),
            Scalar52([
                0x0006_d52b_f200_cfd5, 0x0003_3fb1_d702_1570, 0x000f_201b_c071_39d8,
                0x0001_267e_3e49_169e, 0x0000_07b8_39c0_0268,
            ]))

        // a + b = 0 and a - b
        XCTAssertEqual(Scalar52.add(a, b), .zero)
        XCTAssertEqual(
            Scalar52.sub(a, b),
            Scalar52([
                0x000a_46d8_0f67_7d12, 0x0003_787a_54cf_8188, 0x0004_954f_0555_c7dc,
                0x000d_67ed_c9fd_8989, 0x0000_0a65_b53f_5718,
            ]))

        // (2^512 - 1) mod ℓ
        XCTAssertEqual(
            Scalar52.fromBytesWide([UInt8](repeating: 255, count: 64)),
            Scalar52([
                0x0006_11e3_449c_0f00, 0x000a_7688_5934_7a40, 0x0007_f5be_65d0_0e1b,
                0x0009_a3dc_eec7_3d21, 0x0000_0399_411b_7c30,
            ]))
    }

    func testScalar52RoundTrip() {
        let bytes = (0..<32).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ 7) }
        XCTAssertEqual(Scalar52.fromBytes(bytes).asBytes(), bytes)

        // A scalar below ℓ survives a byte round trip unchanged; adding the
        // order wraps to the same value.
        let one = Scalar52.fromBytes([1] + [UInt8](repeating: 0, count: 31))
        XCTAssertEqual(Scalar52.add(one, .zero).asBytes(), one.asBytes())
        XCTAssertEqual(Scalar52.sub(one, one), .zero)
        XCTAssertEqual(Scalar52.add(Scalar52.order, one).asBytes(), one.asBytes())
    }

    // MARK: Noise

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

