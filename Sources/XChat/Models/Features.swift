/// The feature switches `GET /2/chat/features` serves, and the fetch policy
/// an app follows to read them.
///
/// The endpoint answers `{"features": {"v1_send": true}}`. The app performs
/// the GET (the SDK never does) and passes the status and body to
/// `XChatCore.applyFeatures(statusCode:body:)`. Every switch is off until an
/// answer turns it on, and each accepted answer replaces the one before, so
/// the send format stays v0 until an answer says otherwise.
public struct FeatureSwitches: Sendable, Equatable {
    /// The switch names the last accepted answer turned on.
    public var enabled: Set<String>

    public init(enabled: Set<String> = []) {
        self.enabled = enabled
    }

    /// Whether sends use the v1 wire format (per-message keys).
    public var v1Send: Bool { enabled.contains(FeatureFetch.v1SendFlag) }

    /// Every switch off: the state until an answer turns one on.
    public static let off = FeatureSwitches()
}

/// The endpoint, limits and timings the feature fetch follows.
public enum FeatureFetch {
    /// The flag that switches sends from v0 to v1.
    public static let v1SendFlag = "v1_send"

    /// `GET /2/chat/features`, requested without credentials.
    public static let endpoint = "https://api.x.com/2/chat/features"

    /// Largest response body accepted, in bytes.
    public static let maxBodyBytes = 64 * 1024

    /// How long a request may take, body included, in milliseconds.
    public static let timeoutMilliseconds = 2_000

    /// How long after an answer to read again, and the longest retry wait,
    /// in milliseconds.
    public static let refreshMilliseconds = 300_000

    /// The wait before the first retry of a failed read, in milliseconds.
    public static let firstRetryDelayMilliseconds = 1_000

    /// The bucket a request carries for `userId`: its last four digits, or
    /// nil when the id is not a string of digits.
    public static func bucket(userId: String) -> UInt16? {
        guard !userId.isEmpty, userId.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return nil
        }
        return UInt16(userId.suffix(4))
    }

    /// The URL to GET: `endpoint`, with the sender's bucket when known.
    public static func url(endpoint: String = FeatureFetch.endpoint, userId: String?) -> String {
        url(endpoint: endpoint, bucket: userId.flatMap(bucket))
    }

    /// The URL to GET: `endpoint`, with `bucket` appended when present.
    public static func url(endpoint: String = FeatureFetch.endpoint, bucket: UInt16?) -> String {
        guard let bucket else { return endpoint }
        let separator = endpoint.contains("?") ? "&" : "?"
        return "\(endpoint)\(separator)bucket=\(bucket)"
    }

    /// The wait before the read that follows `failures` failed reads in a
    /// row: one second, doubling, never more than a refresh.
    public static func retryDelayMilliseconds(failures: Int) -> UInt64 {
        guard failures > 0 else { return 0 }
        let shift = min(failures - 1, 32)
        let delay = UInt64(firstRetryDelayMilliseconds) << UInt64(shift)
        return min(delay, UInt64(refreshMilliseconds))
    }
}
