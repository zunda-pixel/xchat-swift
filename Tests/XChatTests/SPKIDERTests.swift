import Testing
@testable import XChat

struct SPKIDERTests {
    // The registration encoding produced for the fixture identity key before the migration.
    private static let legacyIdentitySPKI =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="

    @Test func legacyEncodingAndFingerprintMatch() throws {
        let publicKey = TestVectors.bytes("identity_public_b64")
        let legacyDER = try Base64.decodeStandard(Self.legacyIdentitySPKI)
        #expect(try spkiDER(publicKey: publicKey) == legacyDER)

        let core = XChatCore()
        try core.importKeys(identityPrivateKey: TestVectors.bytes("identity_private_b64"))
        #expect(try core.getPublicKeyFingerprint() == "XNJS-wzokyQ2-vjM0QQJgbie5K1rn-niorfnGqyyfNM")
    }

    @Test func legacyIdentitySPKICanEncrypt() throws {
        let publicKey = try Base64.decodeStandard(Self.legacyIdentitySPKI)
        let privateKey = TestVectors.bytes("identity_private_b64")
        let message = Array(TestVectors.string("message_utf8").utf8)
        let ciphertext = try encryptWithPublicKey(publicKey: publicKey, data: message)

        #expect(try decryptWithPrivateKey(privateKey: privateKey, data: ciphertext) == message)
    }

    @Test func referenceSignatureVerifiesWithSEC1AndSPKI() throws {
        let publicKey = TestVectors.bytes("signing_public_b64")
        let compressed = [UInt8(0x03)] + publicKey[1...32]
        let legacyDER = try Base64.decodeStandard(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI/EdmmXgHd1UQ247QQCk9msafdDDbun2t5jzpgimeBLedInhz0Q=="
        )
        let signature = TestVectors.bytes("signature_b64")
        let message = Array(TestVectors.string("message_utf8").utf8)

        for encoding in [publicKey, compressed, legacyDER] {
            #expect(try verify(publicKey: encoding, signature: signature, payload: message))
        }
    }

    @Test func v10EventSignatureVerifiesWithSPKI() throws {
        let publicKey = TestVectors.bytes("signature_v10_cev1_public_key_b64")
        let signature = TestVectors.bytes("signature_v10_cev1_b64")
        let message = Array(TestVectors.string("payload_message_v10_cev1").utf8)
        let differentMessage = Array(TestVectors.string("payload_message_v10").utf8)

        #expect(try verify(publicKey: publicKey, signature: signature, payload: message))
        #expect(try !verify(publicKey: publicKey, signature: signature, payload: differentMessage))
    }

    @Test func rejectsMalformedSPKIAndWrongCurve() throws {
        let publicKey = TestVectors.bytes("signature_v10_cev1_public_key_b64")
        let signature = TestVectors.bytes("signature_v10_cev1_b64")
        let message = Array(TestVectors.string("payload_message_v10_cev1").utf8)
        var wrongCurve = publicKey
        // Change the last arc of the named-curve OID while keeping the point.
        wrongCurve[22] = 0x02
        var malformed = publicKey
        malformed[0] = 0x31

        for invalidKey in [malformed, wrongCurve, publicKey + [0]] {
            let error = #expect(throws: XChatError.self) {
                try verify(publicKey: invalidKey, signature: signature, payload: message)
            }
            #expect(error?.kind == .invalidInput)
        }
    }
}
