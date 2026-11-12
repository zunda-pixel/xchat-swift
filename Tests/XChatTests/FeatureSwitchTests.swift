import Testing
import XCTest

@testable import XChat

/// The feature switches `GET /2/chat/features` serves: what an answer turns
/// on, the fail-closed rules around it, the request URL, and the retry
/// schedule the app follows.
final class FeatureSwitchTests: XCTestCase {
    private func body(_ json: String) -> [UInt8] {
        Array(json.utf8)
    }

    // MARK: Applying answers

    func testAcceptedAnswerTurnsOnV1Send() {
        let core = XChatCore()
        XCTAssertFalse(core.features.v1Send)
        XCTAssertEqual(core.sendVersion, .v0)

        XCTAssertTrue(
            core.applyFeatures(
                statusCode: 200, body: body(#"{"features":{"v1_send":true}}"#)))
        XCTAssertTrue(core.features.v1Send)
        XCTAssertEqual(core.sendVersion, .v1)

        // Another answer replaces the switches.
        XCTAssertTrue(
            core.applyFeatures(
                statusCode: 200, body: body(#"{"features":{"v1_send":false}}"#)))
        XCTAssertFalse(core.features.v1Send)
        XCTAssertEqual(core.sendVersion, .v0)

        // An answer without the flag turns it off too.
        XCTAssertTrue(
            core.applyFeatures(statusCode: 200, body: body(#"{"features":{}}"#)))
        XCTAssertFalse(core.features.v1Send)
    }

    /// Anything that is not a 200 features object leaves the switches alone.
    func testRejectedAnswersChangeNothing() {
        let core = XChatCore()
        core.applyFeatures(statusCode: 200, body: body(#"{"features":{"v1_send":true}}"#))

        let rejected: [(Int, [UInt8])] = [
            (500, body(#"{"features":{"v1_send":false}}"#)),
            (404, body(#"{"features":{"v1_send":false}}"#)),
            (200, body("not json")),
            (200, body(#"{"other":{}}"#)),
            (200, body(#"{"features":[]}"#)),
            (200, []),
            (200, [UInt8](repeating: 0x20, count: FeatureFetch.maxBodyBytes + 1)),
        ]
        for (status, bytes) in rejected {
            XCTAssertFalse(core.applyFeatures(statusCode: status, body: bytes), "\(status)")
            XCTAssertTrue(core.features.v1Send, "a rejected answer must change nothing")
            XCTAssertEqual(core.sendVersion, .v1)
        }
    }

    /// An accepted answer switches the send format end to end: the next
    /// message carries contents_encryption_version 1.
    func testV1SendFromFeaturesReachesTheWire() throws {
        let signingPair = generateKeyPair()
        let core = XChatCore()
        try core.importKeys(
            identityPrivateKey: generateKeyPair().privateKey,
            signingPrivateKey: signingPair.privateKey, publicKeyVersion: "1")
        core.applyFeatures(statusCode: 200, body: body(#"{"features":{"v1_send":true}}"#))

        let payload = try core.encryptMessage(
            text: "hi", conversationId: "1111:2222",
            conversationKey: TestVectors.bytes("conversation_key_b64"),
            conversationKeyVersion: "1001", senderId: "1111")
        var reader = ThriftReader(try Base64.decodeStandard(payload.encodedMessageCreateEvent))
        let createEvent = try MessageCreateEvent.read(&reader)
        XCTAssertEqual(createEvent.contentsEncryptionVersion, 1)
    }

    // MARK: Request URL

    func testBucketIsTheLastFourDigits() {
        XCTAssertEqual(FeatureFetch.bucket(userId: "123456789"), 6789)
        XCTAssertEqual(FeatureFetch.bucket(userId: "12"), 12)
        XCTAssertEqual(FeatureFetch.bucket(userId: "0000"), 0)
        XCTAssertNil(FeatureFetch.bucket(userId: ""))
        XCTAssertNil(FeatureFetch.bucket(userId: "12a4"))
        XCTAssertNil(FeatureFetch.bucket(userId: "-123"))
    }

    func testRequestURL() {
        XCTAssertEqual(
            FeatureFetch.url(userId: "123456789"),
            "https://api.x.com/2/chat/features?bucket=6789")
        XCTAssertEqual(
            FeatureFetch.url(userId: "abc"),
            "https://api.x.com/2/chat/features")
        XCTAssertEqual(
            FeatureFetch.url(endpoint: "https://example.com/features?x=1", userId: "42"),
            "https://example.com/features?x=1&bucket=42")
        XCTAssertEqual(
            FeatureFetch.url(endpoint: "https://example.com/features", bucket: nil),
            "https://example.com/features")
    }

    // MARK: Retry schedule

    func testRetryDelayDoublesAndCaps() {
        XCTAssertEqual(FeatureFetch.retryDelayMilliseconds(failures: 0), 0)
        XCTAssertEqual(FeatureFetch.retryDelayMilliseconds(failures: 1), 1_000)
        XCTAssertEqual(FeatureFetch.retryDelayMilliseconds(failures: 2), 2_000)
        XCTAssertEqual(FeatureFetch.retryDelayMilliseconds(failures: 3), 4_000)
        XCTAssertEqual(FeatureFetch.retryDelayMilliseconds(failures: 10), 300_000)
        XCTAssertEqual(FeatureFetch.retryDelayMilliseconds(failures: 100), 300_000)
    }
}

/// Only JSON booleans can enable a switch.
@Test func featureSwitchesIgnoreNonBooleanValues() {
    let json = """
        {"features":{"v1_send":1,"string":"true","null":null,"enabled":true,
                     "disabled":false,"array":[true],"object":{"value":true}},
         "ignored":"x"}
        """
    #expect(XChatCore.parseFeatures(Array(json.utf8)) == ["enabled"])
}
