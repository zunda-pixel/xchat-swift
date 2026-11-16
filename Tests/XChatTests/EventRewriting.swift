@testable import XChat

/// `eventB64` re-encoded after `change`. The signature no longer matches,
/// which neither opening a message's media nor quoting a message checks.
func rewritingEvent(
  _ eventB64: String, _ change: (inout MessageEvent) -> Void
) throws -> String {
  var event = try XChatCore().parseEvent(eventB64)
  change(&event)
  var writer = ThriftWriter()
  event.write(to: &writer)
  return Base64.encodeStandard(writer.data)
}

/// `eventB64` with its message's contents replaced by `contents`.
func replacingContents(_ eventB64: String, with contents: [UInt8]?) throws -> String {
  try rewritingEvent(eventB64) { event in
    guard case .messageCreate(var create)? = event.detail else { return }
    create.contents = contents
    event.detail = .messageCreate(create)
  }
}
