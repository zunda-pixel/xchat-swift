import Foundation

@testable import XChat

/// The cross-binding vectors in `sdk_vectors.json`, copied into the test
/// bundle. The fixture is produced by the core, so matching it proves
/// interoperability rather than self-consistency.
enum TestVectors {
    /// A required string field.
    static func string(_ field: String) -> String {
        guard let value = all[field]?.string else {
            fatalError("sdk_vectors.json has no string field '\(field)'")
        }
        return value
    }

    /// A required base64 field, decoded as the standard alphabet.
    static func bytes(_ field: String) -> [UInt8] {
        do {
            return try Base64.decodeStandard(string(field))
        } catch {
            fatalError("sdk_vectors.json field '\(field)' is not standard base64: \(error)")
        }
    }

    private static let all: [String: Field] = {
        guard
            let url = Bundle.module.url(forResource: "sdk_vectors", withExtension: "json"),
            let data = try? Data(contentsOf: url),
            let object = try? JSONDecoder().decode([String: Field].self, from: data)
        else {
            fatalError("sdk_vectors.json is missing or unreadable in the test bundle")
        }
        return object
    }()

    private struct Field: Decodable, Sendable {
        var string: String?

        init(from decoder: any Decoder) throws {
            let value = try decoder.singleValueContainer()
            string = try? value.decode(String.self)
        }
    }
}
