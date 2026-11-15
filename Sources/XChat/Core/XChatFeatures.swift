import Foundation

extension XChatCore {
  /// Applies a `GET /2/chat/features` answer, given the status and body as
  /// received.
  ///
  /// An accepted answer (200, body at most 64 KiB, JSON with a `features`
  /// object) replaces the switches and picks the send format: v1 while
  /// `v1_send` is on, else v0. Only a member whose value is the JSON `true`
  /// turns its switch on; any other value (`false`, null, a number, a string,
  /// an array, an object) reads off and does not reject the answer. The body
  /// is checked only as far as `JSONDecoder` reads it: a malformed number or
  /// string is not caught, so the answer is still accepted when one is a
  /// member's value (which reads off) or sits in another top-level member.
  /// Any other answer changes nothing, so a failed read leaves the previous
  /// answer in force. Returns whether the answer was accepted.
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
  /// a JSON object with a `features` object, or when a member fails to decode
  /// for a reason other than its type. Members whose value is not a boolean
  /// read off; other top-level members are ignored.
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

    /// Only a JSON boolean can turn a switch on. Any other value (null, a
    /// number, a string, an array, an object) reads off rather than failing:
    /// throwing would reject the whole answer, so one member the server
    /// changes would keep every other switch from applying. Null is checked
    /// with `decodeNil()` first: `SingleValueDecodingContainer` documents
    /// `valueNotFound` for it, and the JSON decoder added in
    /// swiftlang/swift-foundation#2263 (not in 6.4.x) throws that (Foundation
    /// in Swift 6.4 and on macOS 27.2 reports `typeMismatch`). A failure
    /// other than a type mismatch still throws (although JSONDecoder reports
    /// none here): the protocol documents only those two for a value, so any
    /// other failure means broken data or a broken decoder, and the answer is
    /// rejected like a broken body.
    init(from decoder: any Decoder) throws {
      let value = try decoder.singleValueContainer()
      if value.decodeNil() {
        isEnabled = false
        return
      }
      do {
        isEnabled = try value.decode(Bool.self)
      } catch DecodingError.typeMismatch {
        isEnabled = false
      }
    }
  }
}
