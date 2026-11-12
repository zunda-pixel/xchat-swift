import Foundation

extension XChatCore {
  /// Applies a `GET /2/chat/features` answer, given the status and body as
  /// received.
  ///
  /// An accepted answer (200, body at most 64 KiB, JSON with a `features`
  /// object) replaces the switches and picks the send format: v1 while
  /// `v1_send` is on, else v0. Anything else changes nothing, so a failed
  /// read leaves the previous answer in force. Returns whether the answer
  /// was accepted.
  @discardableResult
  public func applyFeatures(statusCode: Int, body: [UInt8]) -> Bool {
    guard statusCode == 200, body.count <= FeatureFetch.maxBodyBytes,
      let enabled = Self.parseFeatures(body)
    else { return false }
    features = FeatureSwitches(enabled: enabled)
    sendVersion = features.v1Send ? .v1 : .v0
    return true
  }

  /// The switch names a response body turns on, or nil when the body is not
  /// a JSON object with a `features` object. Members whose value is not a
  /// boolean read off; other top-level members are ignored.
  static func parseFeatures(_ body: [UInt8]) -> Set<String>? {
    guard let response = try? JSONDecoder().decode(FeatureResponse.self, from: Data(body))
    else { return nil }
    return Set(
      response.features.compactMap { name, flag in
        flag.isEnabled ? name : nil
      })
  }

  private struct FeatureResponse: Decodable {
    var features: [String: FeatureFlag]
  }

  private struct FeatureFlag: Decodable {
    var isEnabled: Bool

    init(from decoder: any Decoder) throws {
      let value = try decoder.singleValueContainer()
      isEnabled = (try? value.decode(Bool.self)) == true
    }
  }
}
