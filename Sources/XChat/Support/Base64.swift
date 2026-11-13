import Foundation

/// The two unpadded base64 alphabets the X Chat protocol uses: the standard
/// one for keys, payloads and signatures, the URL-safe one for key
/// fingerprints. Decoding accepts both padded and unpadded input.
public enum Base64 {
  private static let standard = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
  private static let urlSafe = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

  /// Encode with the standard alphabet, no padding — matching the
  /// `STANDARD_NO_PAD` engine chat-xdk uses on the wire.
  public static func encodeStandard(_ data: [UInt8]) -> String {
    encode(data, alphabet: standard)
  }

  /// Encode with the standard alphabet and padding — the form the X API's
  /// event and payload fields carry.
  public static func encodeStandardPadded(_ data: [UInt8]) -> String {
    let unpadded = encodeStandard(data)
    switch data.count % 3 {
    case 1: return unpadded + "=="
    case 2: return unpadded + "="
    default: return unpadded
    }
  }

  /// Encode with the URL-safe alphabet, no padding — matching
  /// `URL_SAFE_NO_PAD`, used for public-key fingerprints.
  public static func encodeURLSafe(_ data: [UInt8]) -> String {
    encode(data, alphabet: urlSafe)
  }

  /// Decode standard-alphabet input; padding optional, whitespace rejected.
  public static func decodeStandard(_ string: String) throws -> [UInt8] {
    try decode(string, alphabet: standard)
  }

  /// Decode URL-safe-alphabet input; padding optional, whitespace rejected.
  public static func decodeURLSafe(_ string: String) throws -> [UInt8] {
    try decode(string, alphabet: urlSafe)
  }

  private static func encode(_ data: [UInt8], alphabet: [UInt8]) -> String {
    var out = [UInt8]()
    out.reserveCapacity((data.count + 2) / 3 * 4)
    var i = 0
    while i + 3 <= data.count {
      let n = UInt32(data[i]) << 16 | UInt32(data[i + 1]) << 8 | UInt32(data[i + 2])
      out.append(alphabet[Int(n >> 18 & 0x3f)])
      out.append(alphabet[Int(n >> 12 & 0x3f)])
      out.append(alphabet[Int(n >> 6 & 0x3f)])
      out.append(alphabet[Int(n & 0x3f)])
      i += 3
    }
    let rem = data.count - i
    if rem == 1 {
      let n = UInt32(data[i]) << 16
      out.append(alphabet[Int(n >> 18 & 0x3f)])
      out.append(alphabet[Int(n >> 12 & 0x3f)])
    } else if rem == 2 {
      let n = UInt32(data[i]) << 16 | UInt32(data[i + 1]) << 8
      out.append(alphabet[Int(n >> 18 & 0x3f)])
      out.append(alphabet[Int(n >> 12 & 0x3f)])
      out.append(alphabet[Int(n >> 6 & 0x3f)])
    }
    return String(decoding: out, as: UTF8.self)
  }

  private static func decode(_ string: String, alphabet: [UInt8]) throws -> [UInt8] {
    // Reverse lookup: 0xFF marks bytes that are not part of the alphabet.
    var table = [UInt8](repeating: 0xFF, count: 128)
    for (i, c) in alphabet.enumerated() { table[Int(c)] = UInt8(i) }

    var chars = [UInt8]()
    chars.reserveCapacity(string.utf8.count)
    var padding = 0
    for c in string.utf8 {
      if c == UInt8(ascii: "=") {
        padding += 1
        continue
      }
      if padding > 0 {
        throw XChatError.parse("Invalid base64: '=' is followed by data")
      }
      if c >= 128 || table[Int(c)] == 0xFF {
        throw XChatError.parse("Invalid base64 character: \(String(UnicodeScalar(c)))")
      }
      chars.append(c)
    }
    if padding > 2 || chars.count % 4 == 1 {
      throw XChatError.parse("Invalid base64 length: \(chars.count + padding)")
    }
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 4 * 3)
    var buffer = UInt32(0)
    var bits = 0
    for c in chars {
      buffer = buffer << 6 | UInt32(table[Int(c)])
      bits += 6
      if bits >= 8 {
        bits -= 8
        out.append(UInt8(buffer >> UInt32(bits) & 0xFF))
      }
    }
    return out
  }
}
