import Foundation

/// Thrift binary-protocol field types, with the byte values the wire uses.
///
/// Booleans are `0x02` in a field header followed by a separate value byte;
/// only the compact protocol folds the value into the type. Unknown type
/// bytes are rejected rather than skipped. Parse errors name these types.
public enum ThriftType: UInt8, Sendable {
  case stop = 0x00
  case void = 0x01
  case bool = 0x02
  case byte = 0x03
  case double = 0x04
  case i16 = 0x06
  case i32 = 0x08
  case i64 = 0x0a
  case binary = 0x0b
  case structure = 0x0c
  case map = 0x0d
  case set = 0x0e
  case list = 0x0f
  case uuid = 0x10

  init(wire: UInt8) throws {
    guard let type = ThriftType(rawValue: wire) else {
      throw ThriftError(.unknownType(wire))
    }
    self = type
  }
}

/// One field header: the field's id and type. `stop` ends a struct.
struct ThriftField: Sendable, Equatable {
  let id: Int16
  let type: ThriftType
}

/// What the Thrift reader throws. Only the reader's callers know what was
/// being read (an event, or a message's contents), so they wrap the failure
/// in the matching `XChatError.ParseFailure`; see `readThrift`.
struct ThriftError: Error {
  var failure: XChatError.ThriftFailure

  init(_ failure: XChatError.ThriftFailure) {
    self.failure = failure
  }
}

/// Reads one value from `bytes` with `read`, reporting a malformed encoding
/// as `XChatError.parse(context(failure))`.
func readThrift<T>(
  _ bytes: [UInt8],
  as context: (XChatError.ThriftFailure) -> XChatError.ParseFailure,
  _ read: (inout ThriftReader) throws -> T
) throws -> T {
  var reader = ThriftReader(bytes)
  do {
    return try read(&reader)
  } catch let error as ThriftError {
    throw XChatError.parse(context(error.failure))
  }
}

/// Maximum elements in one list, set, or map.
private let maximumContainerElements = 10_000

/// Maximum cumulative container elements across one document, so nested
/// containers cannot multiply the per-container cap.
private let maximumTotalElements: UInt64 = 100_000

/// Maximum string or binary length, matching the reference's default.
private let maximumBinarySize = 100 * 1024 * 1024

/// Maximum nesting depth while skipping unmodelled values.
private let maximumRecursionDepth = 64

/// A bounded reader for the Thrift simple binary protocol.
///
/// All lengths and counts are validated before allocating, and unknown
/// fields are skipped by their wire type, so hostile input cannot exhaust
/// memory or the stack.
struct ThriftReader {
  private let bytes: [UInt8]
  private var offset = 0
  /// Running total of declared container elements in this document.
  private var totalElements: UInt64 = 0

  init(_ bytes: [UInt8]) {
    self.bytes = bytes
  }

  /// Whether every byte has been consumed.
  var isAtEnd: Bool { offset == bytes.count }

  // MARK: Primitives

  mutating func readByte() throws -> Int8 {
    Int8(bitPattern: try readUInt8())
  }

  mutating func readBool() throws -> Bool {
    // The reference treats any non-zero byte as true.
    try readUInt8() != 0
  }

  mutating func readI16() throws -> Int16 {
    let high = UInt16(try readUInt8()) << 8
    return Int16(bitPattern: high | UInt16(try readUInt8()))
  }

  mutating func readI32() throws -> Int32 {
    var value: UInt32 = 0
    for _ in 0..<4 { value = value << 8 | UInt32(try readUInt8()) }
    return Int32(bitPattern: value)
  }

  mutating func readI64() throws -> Int64 {
    var value: UInt64 = 0
    for _ in 0..<8 { value = value << 8 | UInt64(try readUInt8()) }
    return Int64(bitPattern: value)
  }

  mutating func readDouble() throws -> Double {
    var value: UInt64 = 0
    for _ in 0..<8 { value = value << 8 | UInt64(try readUInt8()) }
    return Double(bitPattern: value)
  }

  mutating func readBinary() throws -> [UInt8] {
    let length = try readI32()
    guard length >= 0 else {
      throw ThriftError(.negativeSize(.binary, length))
    }
    guard Int(length) <= maximumBinarySize else {
      throw ThriftError(.sizeExceedsMaximum(.binary, length, maximum: maximumBinarySize))
    }
    return Array(try readBytes(Int(length)))
  }

  mutating func readString() throws -> String {
    let bytes = try readBinary()
    guard let string = String(bytes: bytes, encoding: .utf8) else {
      throw ThriftError(.invalidUTF8)
    }
    return string
  }

  // MARK: Structure

  mutating func readFieldBegin() throws -> ThriftField {
    let type = try ThriftType(wire: try readUInt8())
    if type == .stop {
      return ThriftField(id: 0, type: .stop)
    }
    return ThriftField(id: try readI16(), type: type)
  }

  mutating func readListBegin() throws -> (elementType: ThriftType, count: Int) {
    let elementType = try ThriftType(wire: try readUInt8())
    return (elementType, try readContainerCount(.list))
  }

  mutating func readSetBegin() throws -> (elementType: ThriftType, count: Int) {
    let elementType = try ThriftType(wire: try readUInt8())
    return (elementType, try readContainerCount(.set))
  }

  mutating func readMapBegin() throws -> (
    keyType: ThriftType, valueType: ThriftType, count: Int
  ) {
    let keyType = try ThriftType(wire: try readUInt8())
    let valueType = try ThriftType(wire: try readUInt8())
    return (keyType, valueType, try readContainerCount(.map))
  }

  /// Skips one value of `type`, recursing into containers up to a bounded
  /// depth so a hostile encoding cannot exhaust the stack.
  mutating func skip(_ type: ThriftType, depth: Int = 0) throws {
    guard depth <= maximumRecursionDepth else {
      throw ThriftError(.nestingTooDeep(maximum: maximumRecursionDepth))
    }
    switch type {
    case .stop, .void:
      return
    case .bool, .byte:
      _ = try readUInt8()
    case .double:
      _ = try readDouble()
    case .i16:
      _ = try readI16()
    case .i32:
      _ = try readI32()
    case .i64:
      _ = try readI64()
    case .binary:
      _ = try readBinary()
    case .uuid:
      _ = try readBytes(16)
    case .structure:
      var field = try readFieldBegin()
      while field.type != .stop {
        try skip(field.type, depth: depth + 1)
        field = try readFieldBegin()
      }
    case .list, .set:
      var elementType = ThriftType.stop
      var count = 0
      if type == .list {
        (elementType, count) = try readListBegin()
      } else {
        (elementType, count) = try readSetBegin()
      }
      for _ in 0..<count {
        try skip(elementType, depth: depth + 1)
      }
    case .map:
      let (keyType, valueType, count) = try readMapBegin()
      for _ in 0..<count {
        try skip(keyType, depth: depth + 1)
        try skip(valueType, depth: depth + 1)
      }
    }
  }

  // MARK: Internals

  private mutating func readContainerCount(_ container: ThriftType) throws -> Int {
    let count = try readI32()
    guard count >= 0 else {
      throw ThriftError(.negativeSize(container, count))
    }
    guard count <= maximumContainerElements else {
      throw ThriftError(
        .sizeExceedsMaximum(container, count, maximum: maximumContainerElements))
    }
    totalElements = totalElements &+ UInt64(count)
    guard totalElements <= maximumTotalElements else {
      throw ThriftError(
        .totalElementsExceedMaximum(totalElements, maximum: maximumTotalElements))
    }
    return Int(count)
  }

  private mutating func readUInt8() throws -> UInt8 {
    guard offset < bytes.count else {
      throw ThriftError(.unexpectedEnd)
    }
    let value = bytes[offset]
    offset += 1
    return value
  }

  private mutating func readBytes(_ count: Int) throws -> ArraySlice<UInt8> {
    guard count <= bytes.count - offset else {
      throw ThriftError(.unexpectedEnd)
    }
    let slice = bytes[offset..<offset + count]
    offset += count
    return slice
  }
}

/// Writes the Thrift simple binary protocol.
struct ThriftWriter {
  private var bytes: [UInt8] = []

  /// The encoded bytes.
  var data: [UInt8] { bytes }

  mutating func writeByte(_ value: Int8) {
    bytes.append(UInt8(bitPattern: value))
  }

  mutating func writeBool(_ value: Bool) {
    bytes.append(value ? 1 : 0)
  }

  mutating func writeI16(_ value: Int16) {
    let bits = UInt16(bitPattern: value)
    bytes.append(UInt8(truncatingIfNeeded: bits >> 8))
    bytes.append(UInt8(truncatingIfNeeded: bits))
  }

  mutating func writeI32(_ value: Int32) {
    let bits = UInt32(bitPattern: value)
    for shift in [24, 16, 8, 0] {
      bytes.append(UInt8(truncatingIfNeeded: bits >> UInt32(shift)))
    }
  }

  mutating func writeI64(_ value: Int64) {
    let bits = UInt64(bitPattern: value)
    for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
      bytes.append(UInt8(truncatingIfNeeded: bits >> UInt64(shift)))
    }
  }

  mutating func writeDouble(_ value: Double) {
    writeI64(Int64(bitPattern: value.bitPattern))
  }

  mutating func writeBinary(_ value: [UInt8]) {
    precondition(value.count <= Int(Int32.max), "Thrift values are Int32-length")
    writeI32(Int32(value.count))
    bytes.append(contentsOf: value)
  }

  mutating func writeString(_ value: String) {
    writeBinary(Array(value.utf8))
  }

  mutating func writeFieldBegin(id: Int16, type: ThriftType) {
    bytes.append(type.rawValue)
    writeI16(id)
  }

  mutating func writeFieldStop() {
    bytes.append(ThriftType.stop.rawValue)
  }

  mutating func writeListBegin(elementType: ThriftType, count: Int) {
    bytes.append(elementType.rawValue)
    writeContainerCount(count)
  }

  mutating func writeSetBegin(elementType: ThriftType, count: Int) {
    bytes.append(elementType.rawValue)
    writeContainerCount(count)
  }

  mutating func writeMapBegin(keyType: ThriftType, valueType: ThriftType, count: Int) {
    bytes.append(keyType.rawValue)
    bytes.append(valueType.rawValue)
    writeContainerCount(count)
  }

  private mutating func writeContainerCount(_ count: Int) {
    precondition(count <= Int(Int32.max), "Thrift container counts are Int32")
    writeI32(Int32(count))
  }
}
