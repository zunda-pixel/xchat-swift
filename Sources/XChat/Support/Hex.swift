import Foundation

/// Lowercase hex, as used for conversation keys in test vectors and logs.
public enum Hex {
  public static func encode(_ data: [UInt8]) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    out.reserveCapacity(data.count * 2)
    for byte in data {
      out.append(digits[Int(byte >> 4)])
      out.append(digits[Int(byte & 0x0f)])
    }
    return String(decoding: out, as: UTF8.self)
  }

  public static func decode(_ string: String) throws -> [UInt8] {
    let chars = Array(string.utf8)
    if chars.count % 2 != 0 {
      throw XChatError.parse(.hex(.oddLength(chars.count)))
    }
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
      out.append(try nibble(chars[i]) << 4 | nibble(chars[i + 1]))
      i += 2
    }
    return out
  }

  /// The value of a hex digit; another byte fails without the rest of the
  /// input, which may be a key.
  private static func nibble(_ c: UInt8) throws -> UInt8 {
    switch c {
    case UInt8(ascii: "0")...UInt8(ascii: "9"): c - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"): c - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"): c - UInt8(ascii: "A") + 10
    default: throw XChatError.parse(.hex(.invalidCharacter(c)))
    }
  }
}
