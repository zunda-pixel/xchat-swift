import CoreFoundation
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
        guard let data = try? JSONSerialization.jsonObject(with: Data(body)) as? [String: Any],
            let features = data["features"] as? [String: Any]
        else { return nil }
        var enabled: Set<String> = []
        for (name, value) in features {
            if booleanValue(value) == true {
                enabled.insert(name)
            }
        }
        return enabled
    }

    /// The value of a JSON boolean, or nil for any other JSON value. Foundation
    /// bridges numbers to `Bool`, so only a CFBoolean counts.
    private static func booleanValue(_ value: Any) -> Bool? {
        guard let bool = value as? Bool else { return nil }
        if let number = value as? NSNumber,
            CFGetTypeID(number) != CFBooleanGetTypeID()
        {
            return nil
        }
        return bool
    }
}
