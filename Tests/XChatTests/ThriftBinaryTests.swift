import XCTest

@testable import XChat

/// The Thrift binary protocol: exact encodings, bounds against hostile
/// input, skipping unmodelled values, and decoding the cross-binding
/// vectors' real events.
final class ThriftBinaryTests: XCTestCase {
  // MARK: Exact encodings

  /// The reference implementation's own expectations for field headers.
  func testFieldHeaderEncodings() {
    var writer = ThriftWriter()
    writer.writeFieldBegin(id: 22, type: .binary)
    XCTAssertEqual(writer.data, [0x0B, 0x00, 0x16])

    writer = ThriftWriter()
    writer.writeFieldBegin(id: 102, type: .bool)
    writer.writeBool(true)
    XCTAssertEqual(writer.data, [0x02, 0x00, 0x66, 0x01])

    writer = ThriftWriter()
    writer.writeFieldStop()
    XCTAssertEqual(writer.data, [0x00])
  }

  /// Container headers: element type, then a big-endian count.
  func testContainerHeaderEncodings() {
    var writer = ThriftWriter()
    writer.writeListBegin(elementType: .bool, count: 5)
    XCTAssertEqual(writer.data, [0x02, 0x00, 0x00, 0x00, 0x05])

    writer = ThriftWriter()
    writer.writeSetBegin(elementType: .i16, count: 7)
    XCTAssertEqual(writer.data, [0x06, 0x00, 0x00, 0x00, 0x07])

    writer = ThriftWriter()
    writer.writeMapBegin(keyType: .i64, valueType: .structure, count: 32)
    XCTAssertEqual(writer.data, [0x0A, 0x0C, 0x00, 0x00, 0x00, 0x20])
  }

  func testStringEncoding() {
    var writer = ThriftWriter()
    writer.writeString("hello")
    XCTAssertEqual(writer.data, [0x00, 0x00, 0x00, 0x05] + Array("hello".utf8))
  }

  // MARK: Round trips

  func testPrimitiveRoundTrips() throws {
    var writer = ThriftWriter()
    writer.writeByte(-7)
    writer.writeBool(true)
    writer.writeBool(false)
    writer.writeI16(Int16.min)
    writer.writeI16(Int16.max)
    writer.writeI32(Int32.min)
    writer.writeI32(Int32.max)
    writer.writeI64(Int64.min)
    writer.writeI64(Int64.max)
    writer.writeDouble(3.141592653589793)
    writer.writeString("héllo — 日本")
    writer.writeBinary([0, 1, 2, 255])

    var reader = ThriftReader(writer.data)
    XCTAssertEqual(try reader.readByte(), -7)
    XCTAssertTrue(try reader.readBool())
    XCTAssertFalse(try reader.readBool())
    XCTAssertEqual(try reader.readI16(), Int16.min)
    XCTAssertEqual(try reader.readI16(), Int16.max)
    XCTAssertEqual(try reader.readI32(), Int32.min)
    XCTAssertEqual(try reader.readI32(), Int32.max)
    XCTAssertEqual(try reader.readI64(), Int64.min)
    XCTAssertEqual(try reader.readI64(), Int64.max)
    XCTAssertEqual(try reader.readDouble(), 3.141592653589793)
    XCTAssertEqual(try reader.readString(), "héllo — 日本")
    XCTAssertEqual(try reader.readBinary(), [0, 1, 2, 255])
    XCTAssertTrue(reader.isAtEnd)
  }

  func testStructRoundTripAndSkip() throws {
    // struct { 1: string "a", 2: list<i32> [1, 2], 3: map<i64, string> {5: "x"},
    //          4: struct { 1: bool true } }
    var writer = ThriftWriter()
    writer.writeFieldBegin(id: 1, type: .binary)
    writer.writeString("a")
    writer.writeFieldBegin(id: 2, type: .list)
    writer.writeListBegin(elementType: .i32, count: 2)
    writer.writeI32(1)
    writer.writeI32(2)
    writer.writeFieldBegin(id: 3, type: .map)
    writer.writeMapBegin(keyType: .i64, valueType: .binary, count: 1)
    writer.writeI64(5)
    writer.writeString("x")
    writer.writeFieldBegin(id: 4, type: .structure)
    writer.writeFieldBegin(id: 1, type: .bool)
    writer.writeBool(true)
    writer.writeFieldStop()
    writer.writeFieldStop()
    let bytes = writer.data

    var reader = ThriftReader(bytes)
    XCTAssertEqual(try reader.readFieldBegin().id, 1)
    XCTAssertEqual(try reader.readString(), "a")
    XCTAssertEqual(try reader.readFieldBegin().id, 2)
    let list = try reader.readListBegin()
    XCTAssertEqual(list.elementType, .i32)
    XCTAssertEqual(list.count, 2)
    XCTAssertEqual(try reader.readI32(), 1)
    XCTAssertEqual(try reader.readI32(), 2)
    XCTAssertEqual(try reader.readFieldBegin().id, 3)
    let map = try reader.readMapBegin()
    XCTAssertEqual(map.keyType, .i64)
    XCTAssertEqual(map.valueType, .binary)
    XCTAssertEqual(map.count, 1)
    XCTAssertEqual(try reader.readI64(), 5)
    XCTAssertEqual(try reader.readString(), "x")
    XCTAssertEqual(try reader.readFieldBegin().id, 4)
    XCTAssertEqual(try reader.readFieldBegin().id, 1)
    XCTAssertTrue(try reader.readBool())
    XCTAssertEqual(try reader.readFieldBegin().type, .stop)
    XCTAssertEqual(try reader.readFieldBegin().type, .stop)
    XCTAssertTrue(reader.isAtEnd)

    // The whole struct also skips in one call.
    var skipper = ThriftReader(bytes)
    try skipper.skip(.structure)
    XCTAssertTrue(skipper.isAtEnd)
  }

  // MARK: Bounds

  func testUnknownFieldTypeRejected() {
    var reader = ThriftReader([0x05])
    XCTAssertThrowsError(try reader.readFieldBegin()) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }
    var listReader = ThriftReader([0x05, 0x00, 0x00, 0x00, 0x00])
    XCTAssertThrowsError(try listReader.readListBegin())
  }

  func testTruncatedInputRejected() {
    for bytes: [UInt8] in [[], [0x0B], [0x0B, 0x00], [0x06, 0x00]] {
      var reader = ThriftReader(bytes)
      XCTAssertThrowsError(try reader.readFieldBegin()) { error in
        XCTAssertEqual((error as? XChatError)?.kind, .parse)
      }
    }
    // A field header can be complete while its value is not.
    var reader = ThriftReader([0x06, 0x00, 0x01])
    _ = try? reader.readFieldBegin()
    XCTAssertThrowsError(try reader.readI16())
    var stringReader = ThriftReader([0x00, 0x00, 0x00, 0x05, 0x61])
    XCTAssertThrowsError(try stringReader.readString())
    XCTAssertFalse(stringReader.isAtEnd)
  }

  func testNegativeAndOversizedLengthsRejected() {
    // Negative string length.
    var negative = ThriftReader([0xFF, 0xFF, 0xFF, 0xFF])
    XCTAssertThrowsError(try negative.readBinary())

    // Declared length far above the cap, with no body: rejected before
    // any allocation or read.
    var oversized = ThriftReader([0x07, 0xFF, 0xFF, 0xFF])
    XCTAssertThrowsError(try oversized.readBinary()) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }

    // Negative list count.
    var negativeList = ThriftReader([0x08, 0xFF, 0xFF, 0xFF, 0xFF])
    XCTAssertThrowsError(try negativeList.readListBegin())

    // One element over the per-container cap.
    var tooLarge = ThriftReader([0x08, 0x00, 0x00, 0x27, 0x11])
    XCTAssertThrowsError(try tooLarge.readListBegin()) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }
  }

  /// The cumulative cap is enforced across containers, so nested
  /// containers cannot multiply the per-container cap.
  func testCumulativeContainerCap() throws {
    var headers: [UInt8] = []
    for _ in 0..<11 {
      headers += [0x08, 0x00, 0x00, 0x27, 0x10]  // list<i32> of 10_000
    }
    var reader = ThriftReader(headers)
    for _ in 0..<10 {
      _ = try reader.readListBegin()
    }
    XCTAssertThrowsError(try reader.readListBegin()) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }
  }

  /// Skipping refuses to recurse without bound.
  func testSkipDepthLimit() throws {
    func nestedStructs(_ depth: Int) -> [UInt8] {
      var bytes: [UInt8] = []
      for _ in 0..<depth {
        bytes += [0x0C, 0x00, 0x01]  // field 1: struct
      }
      // One stop per struct plus the innermost empty struct.
      bytes += [UInt8](repeating: 0x00, count: depth + 1)
      return bytes
    }

    var shallow = ThriftReader(nestedStructs(64))
    try shallow.skip(.structure)
    XCTAssertTrue(shallow.isAtEnd)

    var deep = ThriftReader(nestedStructs(70))
    XCTAssertThrowsError(try deep.skip(.structure)) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }
  }

  // MARK: Cross-binding vector events

  /// Decodes a `MessageEvent` envelope: the visible fields, the detail
  /// union's variant tag, and the signature struct.
  private struct Envelope {
    struct Signature {
      var value: String?
      var publicKeyVersion: String?
      var signatureVersion: String?
      var signingPublicKey: String?
    }

    var sequenceId: String?
    var messageId: String?
    var senderId: String?
    var conversationId: String?
    var detailField: ThriftField?
    var signature: Signature?
  }

  private func decodeEnvelope(_ bytes: [UInt8]) throws -> Envelope {
    var reader = ThriftReader(bytes)
    var envelope = Envelope()
    var field = try reader.readFieldBegin()
    while field.type != .stop {
      switch field.id {
      case 1:
        envelope.sequenceId = try reader.readString()
      case 2:
        envelope.messageId = try reader.readString()
      case 3:
        envelope.senderId = try reader.readString()
      case 4:
        envelope.conversationId = try reader.readString()
      case 7:
        // The detail union: record the variant tag, then skip it.
        let variant = try reader.readFieldBegin()
        envelope.detailField = variant
        if variant.type != .stop {
          try reader.skip(variant.type)
        }
        var next = try reader.readFieldBegin()
        while next.type != .stop {
          try reader.skip(next.type)
          next = try reader.readFieldBegin()
        }
      case 9:
        var signature = Envelope.Signature()
        var signatureField = try reader.readFieldBegin()
        while signatureField.type != .stop {
          switch signatureField.id {
          case 1: signature.value = try reader.readString()
          case 2: signature.publicKeyVersion = try reader.readString()
          case 3: signature.signatureVersion = try reader.readString()
          case 4: signature.signingPublicKey = try reader.readString()
          default: try reader.skip(signatureField.type)
          }
          signatureField = try reader.readFieldBegin()
        }
        envelope.signature = signature
      default:
        try reader.skip(field.type)
      }
      field = try reader.readFieldBegin()
    }
    XCTAssertTrue(reader.isAtEnd)
    return envelope
  }

  func testVectorMessageEventEnvelope() throws {
    let envelope = try decodeEnvelope(TestVectors.bytes("event_message_b64"))
    XCTAssertEqual(envelope.sequenceId, "1")
    XCTAssertEqual(envelope.messageId?.count, 36)
    XCTAssertEqual(envelope.senderId, TestVectors.string("event_sender_id"))
    XCTAssertEqual(envelope.conversationId, TestVectors.string("event_conversation_id"))
    XCTAssertEqual(envelope.detailField, ThriftField(id: 1, type: .structure))
    let signature = try XCTUnwrap(envelope.signature)
    XCTAssertNotNil(signature.value)
    XCTAssertNotNil(signature.publicKeyVersion)
    XCTAssertNotNil(signature.signatureVersion)
  }

  func testVectorUnencryptedEventEnvelope() throws {
    let envelope = try decodeEnvelope(TestVectors.bytes("event_unencrypted_b64"))
    XCTAssertEqual(envelope.senderId, TestVectors.string("event_sender_id"))
    XCTAssertEqual(envelope.messageId, "plain-msg-1")
  }

  /// The key-change event's detail is the conversation-key-change variant.
  func testVectorKeyChangeEventEnvelope() throws {
    let envelope = try decodeEnvelope(TestVectors.bytes("event_key_change_b64"))
    XCTAssertEqual(envelope.senderId, TestVectors.string("event_sender_id"))
    XCTAssertEqual(envelope.messageId, "kc-msg-1")
    XCTAssertEqual(envelope.detailField, ThriftField(id: 3, type: .structure))
  }

  func testVectorFailureEventEnvelope() throws {
    let envelope = try decodeEnvelope(TestVectors.bytes("event_failure_b64"))
    XCTAssertEqual(envelope.messageId, "failure-msg-1")
    XCTAssertEqual(envelope.detailField, ThriftField(id: 5, type: .structure))
  }

  /// The garbage vector is not decodable base64; strict decoding rejects it
  /// before any Thrift parsing. Arbitrary bytes are rejected as unknown
  /// field types.
  func testGarbageEventRejected() {
    XCTAssertThrowsError(
      try Base64.decodeStandard(TestVectors.string("event_garbage_b64"))
    ) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }

    var reader = ThriftReader([0x9E, 0x8B, 0x5A, 0x9D, 0xEB, 0xDE, 0x9E])
    XCTAssertThrowsError(try reader.readFieldBegin()) { error in
      XCTAssertEqual((error as? XChatError)?.kind, .parse)
    }
  }

  /// End to end over real bytes: parse the key-change event, take its
  /// participant key, and ECIES-decrypt it with the vector's identity key.
  /// Every layer — Thrift, base64, ECDH, KDF2, AES-GCM with a 16-byte IV —
  /// must agree with the reference.
  func testVectorKeyChangeDecryptsConversationKey() throws {
    let bytes = TestVectors.bytes("event_key_change_b64")
    var reader = ThriftReader(bytes)

    var participantKey: [UInt8]?
    var participantVersion: String?

    var field = try reader.readFieldBegin()
    while field.type != .stop {
      if field.id == 7, field.type == .structure {
        let variant = try reader.readFieldBegin()
        if variant.id == 3, variant.type == .structure {
          var kceField = try reader.readFieldBegin()
          while kceField.type != .stop {
            if kceField.id == 2, kceField.type == .list {
              let list = try reader.readListBegin()
              for _ in 0..<list.count {
                var keyField = try reader.readFieldBegin()
                while keyField.type != .stop {
                  switch keyField.id {
                  case 2:
                    let base64 = try reader.readString()
                    participantKey = try Base64.decodeStandard(base64)
                  case 3:
                    participantVersion = try reader.readString()
                  default:
                    try reader.skip(keyField.type)
                  }
                  keyField = try reader.readFieldBegin()
                }
              }
            } else {
              try reader.skip(kceField.type)
            }
            kceField = try reader.readFieldBegin()
          }
        } else if variant.type != .stop {
          try reader.skip(variant.type)
        }
        var nextVariant = try reader.readFieldBegin()
        while nextVariant.type != .stop {
          try reader.skip(nextVariant.type)
          nextVariant = try reader.readFieldBegin()
        }
      } else {
        try reader.skip(field.type)
      }
      field = try reader.readFieldBegin()
    }

    let encrypted = try XCTUnwrap(participantKey)
    XCTAssertEqual(participantVersion, TestVectors.string("event_recipient_key_version"))
    let conversationKey = try decryptWithPrivateKey(
      privateKey: TestVectors.bytes("identity_private_b64"), data: encrypted)
    XCTAssertEqual(conversationKey, TestVectors.bytes("conversation_key_b64"))
  }
}
