import Testing

@testable import XChat

/// A body `applyFeatures` is given that must leave the switches alone.
struct RejectedFeatureAnswer: Sendable {
  var status: Int
  var body: [UInt8]
}

private func featureBody(_ json: String) -> [UInt8] {
  Array(json.utf8)
}

private let rejectedFeatureAnswers: [RejectedFeatureAnswer] = [
  RejectedFeatureAnswer(
    status: 500, body: featureBody(#"{"features":{"v1_send":false}}"#)),
  RejectedFeatureAnswer(
    status: 404, body: featureBody(#"{"features":{"v1_send":false}}"#)),
  RejectedFeatureAnswer(status: 200, body: featureBody("not json")),
  RejectedFeatureAnswer(status: 200, body: featureBody(#"{"other":{}}"#)),
  RejectedFeatureAnswer(status: 200, body: featureBody(#"{"features":[]}"#)),
  RejectedFeatureAnswer(status: 200, body: []),
  RejectedFeatureAnswer(
    status: 200,
    body: [UInt8](repeating: 0x20, count: FeatureFetch.maxBodyBytes + 1)),
]

/// The feature switches `GET /2/chat/features` serves: what an answer turns
/// on, the fail-closed rules around it, the request URL, and the retry
/// schedule the app follows.
struct FeatureSwitchTests {
  private func body(_ json: String) -> [UInt8] {
    featureBody(json)
  }

  // MARK: Applying answers

  @Test func acceptedAnswerTurnsOnV1Send() {
    let core = XChatCore()
    #expect(!core.features.v1Send)
    #expect(core.sendVersion == .v0)

    #expect(
      core.applyFeatures(
        statusCode: 200, body: body(#"{"features":{"v1_send":true}}"#)))
    #expect(core.features.v1Send)
    #expect(core.sendVersion == .v1)

    // Another answer replaces the switches.
    #expect(
      core.applyFeatures(
        statusCode: 200, body: body(#"{"features":{"v1_send":false}}"#)))
    #expect(!core.features.v1Send)
    #expect(core.sendVersion == .v0)

    // An answer without the flag turns it off too.
    #expect(
      core.applyFeatures(statusCode: 200, body: body(#"{"features":{}}"#)))
    #expect(!core.features.v1Send)
  }

  /// Anything that is not a 200 features object leaves the switches alone.
  @Test(arguments: rejectedFeatureAnswers)
  func rejectedAnswersChangeNothing(answer: RejectedFeatureAnswer) {
    let core = XChatCore()
    core.applyFeatures(statusCode: 200, body: body(#"{"features":{"v1_send":true}}"#))

    #expect(!core.applyFeatures(statusCode: answer.status, body: answer.body), "\(answer.status)")
    #expect(core.features.v1Send, "a rejected answer must change nothing")
    #expect(core.sendVersion == .v1)
  }

  /// An accepted answer switches the send format end to end: the next
  /// message carries contents_encryption_version 1.
  @Test func v1SendFromFeaturesReachesTheWire() throws {
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
    #expect(createEvent.contentsEncryptionVersion == 1)
  }

  // MARK: Request URL

  @Test func bucketIsTheLastFourDigits() {
    #expect(FeatureFetch.bucket(userId: "123456789") == 6789)
    #expect(FeatureFetch.bucket(userId: "12") == 12)
    #expect(FeatureFetch.bucket(userId: "0000") == 0)
    #expect(FeatureFetch.bucket(userId: "") == nil)
    #expect(FeatureFetch.bucket(userId: "12a4") == nil)
    #expect(FeatureFetch.bucket(userId: "-123") == nil)
  }

  @Test func requestURL() {
    #expect(
      FeatureFetch.url(userId: "123456789")
        == "https://api.x.com/2/chat/features?bucket=6789")
    #expect(
      FeatureFetch.url(userId: "abc")
        == "https://api.x.com/2/chat/features")
    #expect(
      FeatureFetch.url(endpoint: "https://example.com/features?x=1", userId: "42")
        == "https://example.com/features?x=1&bucket=42")
    #expect(
      FeatureFetch.url(endpoint: "https://example.com/features", bucket: nil)
        == "https://example.com/features")
  }

  // MARK: Retry schedule

  @Test func retryDelayDoublesAndCaps() {
    #expect(FeatureFetch.retryDelayMilliseconds(failures: 0) == 0)
    #expect(FeatureFetch.retryDelayMilliseconds(failures: 1) == 1_000)
    #expect(FeatureFetch.retryDelayMilliseconds(failures: 2) == 2_000)
    #expect(FeatureFetch.retryDelayMilliseconds(failures: 3) == 4_000)
    #expect(FeatureFetch.retryDelayMilliseconds(failures: 10) == 300_000)
    #expect(FeatureFetch.retryDelayMilliseconds(failures: 100) == 300_000)
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
