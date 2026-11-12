/// Helpers shared by the typed Thrift models: every field is checked
/// against its declared wire type before its value is read, and unknown
/// fields are skipped by their wire type.

/// Ensures a field's wire type matches the struct's declared type.
func expectField(_ field: ThriftField, _ type: ThriftType, _ name: String) throws {
  guard field.type == type else {
    throw XChatError.parse(
      "Thrift field \(name) (#\(field.id)) is \(field.type), expected \(type)")
  }
}

func readBoolField(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> Bool {
  try expectField(field, .bool, name)
  return try reader.readBool()
}

func readI16Field(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> Int16 {
  try expectField(field, .i16, name)
  return try reader.readI16()
}

func readI32Field(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> Int32 {
  try expectField(field, .i32, name)
  return try reader.readI32()
}

func readI64Field(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> Int64 {
  try expectField(field, .i64, name)
  return try reader.readI64()
}

func readStringField(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> String {
  try expectField(field, .binary, name)
  return try reader.readString()
}

func readBinaryField(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> [UInt8] {
  try expectField(field, .binary, name)
  return try reader.readBinary()
}

func readStringList(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> [String] {
  try expectField(field, .list, name)
  let list = try reader.readListBegin()
  guard list.elementType == .binary else {
    throw XChatError.parse("Thrift list \(name) has element type \(list.elementType)")
  }
  var items: [String] = []
  items.reserveCapacity(list.count)
  for _ in 0..<list.count {
    items.append(try reader.readString())
  }
  return items
}

func readStructList<T>(
  _ field: ThriftField,
  _ name: String,
  _ reader: inout ThriftReader,
  _ parse: (inout ThriftReader) throws -> T
) throws -> [T] {
  try expectField(field, .list, name)
  let list = try reader.readListBegin()
  guard list.elementType == .structure else {
    throw XChatError.parse("Thrift list \(name) has element type \(list.elementType)")
  }
  var items: [T] = []
  items.reserveCapacity(list.count)
  for _ in 0..<list.count {
    items.append(try parse(&reader))
  }
  return items
}

func readStringMap(
  _ field: ThriftField, _ name: String, _ reader: inout ThriftReader
) throws -> [String: String] {
  try expectField(field, .map, name)
  let map = try reader.readMapBegin()
  guard map.keyType == .binary, map.valueType == .binary else {
    throw XChatError.parse(
      "Thrift map \(name) is \(map.keyType) to \(map.valueType), expected string to string")
  }
  var values: [String: String] = [:]
  values.reserveCapacity(map.count)
  for _ in 0..<map.count {
    let key = try reader.readString()
    values[key] = try reader.readString()
  }
  return values
}
