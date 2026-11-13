/// Little-endian readers and writers shared by the hand-rolled cipher and
/// MAC implementations, whose wire formats are all little-endian words.
extension Collection where Element == UInt8, Index == Int {
  /// Reads a little-endian UInt32 `offset` bytes into the receiver.
  /// Works on both arrays and slices; slices are indexed from their own
  /// start.
  func le32(at offset: Int) -> UInt32 {
    let i = startIndex + offset
    return UInt32(self[i])
      | UInt32(self[i + 1]) << 8
      | UInt32(self[i + 2]) << 16
      | UInt32(self[i + 3]) << 24
  }

  /// Reads a little-endian UInt64 `offset` bytes into the receiver.
  func le64(at offset: Int) -> UInt64 {
    let i = startIndex + offset
    var value: UInt64 = 0
    for j in 0..<8 { value |= UInt64(self[i + j]) << (8 * UInt64(j)) }
    return value
  }
}

extension UInt32 {
  /// The value as 4 little-endian bytes.
  var leBytes: [UInt8] {
    [
      UInt8(truncatingIfNeeded: self),
      UInt8(truncatingIfNeeded: self >> 8),
      UInt8(truncatingIfNeeded: self >> 16),
      UInt8(truncatingIfNeeded: self >> 24),
    ]
  }
}

extension UInt64 {
  /// The value as 8 little-endian bytes.
  var leBytes: [UInt8] {
    [
      UInt8(truncatingIfNeeded: self),
      UInt8(truncatingIfNeeded: self >> 8),
      UInt8(truncatingIfNeeded: self >> 16),
      UInt8(truncatingIfNeeded: self >> 24),
      UInt8(truncatingIfNeeded: self >> 32),
      UInt8(truncatingIfNeeded: self >> 40),
      UInt8(truncatingIfNeeded: self >> 48),
      UInt8(truncatingIfNeeded: self >> 56),
    ]
  }
}
