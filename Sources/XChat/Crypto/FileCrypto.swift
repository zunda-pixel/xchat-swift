/// Streaming media encryption over `crypto_secretstream_xchacha20poly1305`.
///
/// Wire format, frozen against every other X Chat client:
/// ```text
/// header (24 bytes) || chunk_0 || chunk_1 || … || chunk_n
/// ```
/// Each chunk is (plaintext_len + 17) bytes. Intermediate chunks carry the
/// message tag; the final chunk carries the final tag.

/// Size of the secretstream header.
private let streamHeaderSize = 24

/// Plaintext bytes per chunk.
private let decryptedChunkSize = 1024

/// Per-chunk overhead: one tag byte plus a 16-byte MAC.
private let chunkOverhead = 17

/// Ciphertext bytes per chunk: plaintext chunk plus overhead.
private let encryptedChunkSize = decryptedChunkSize + chunkOverhead

/// The exact ciphertext size `encryptFile` and `FileEncryptor` produce for
/// `plaintextSize` bytes of plaintext. Returns nil when the size cannot be
/// represented as a UInt64.
public func encryptedFileSize(_ plaintextSize: UInt64) -> UInt64? {
    if plaintextSize == 0 {
        return UInt64(streamHeaderSize)
    }
    let chunkCount =
        plaintextSize / UInt64(decryptedChunkSize)
        + (plaintextSize % UInt64(decryptedChunkSize) == 0 ? 0 : 1)
    let (overhead, overheadOverflow) =
        chunkCount.multipliedReportingOverflow(by: UInt64(chunkOverhead))
    if overheadOverflow { return nil }
    let (withHeader, headerOverflow) =
        overhead.addingReportingOverflow(UInt64(streamHeaderSize))
    if headerOverflow { return nil }
    let (total, totalOverflow) = withHeader.addingReportingOverflow(plaintextSize)
    if totalOverflow { return nil }
    return total
}

/// Incremental encryptor for one file.
///
/// Feed plaintext with `push` and call `finish` once to emit the terminating
/// frame. Plaintext is framed into 1024-byte chunks; intermediate chunks
/// carry the message tag and the last chunk carries the final tag, so
/// framing is identical regardless of how the input is split across `push`
/// calls. Empty input (no non-empty `push`) produces only the 24-byte
/// header. Copying an encryptor would reuse its stream nonce for the next
/// frame, so each encryptor has one owner.
public struct FileEncryptor: ~Copyable {
    /// Underlying secretstream pusher.
    private var stream: SecretStreamPush
    /// Header bytes, emitted ahead of the first frame.
    private var prefix: [UInt8]
    /// Plaintext held until a full chunk is available; at most one chunk.
    private var buf: [UInt8]
    /// Whether any non-empty plaintext has been pushed.
    private var started: Bool
    /// Set after emitting the last frame.
    private var finished: Bool

    /// Creates an encryptor for one file under a 32-byte conversation key.
    public init(key: [UInt8]) throws {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        let (header, pusher) = try SecretStreamPush.start(key: key)
        stream = pusher
        prefix = header
        buf = []
        started = false
        finished = false
    }

    /// Encrypts a plaintext chunk, returning the ciphertext available so
    /// far. The last full chunk is held back so `finish` can tag the final
    /// frame, so the returned bytes may be empty for small inputs.
    public mutating func push(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard !finished else {
            throw XChatError.invalidInput("File encryptor already finished")
        }
        var out = prefix
        prefix = []
        if !plaintext.isEmpty {
            started = true
            buf += plaintext
        }
        var offset = 0
        while buf.count - offset > decryptedChunkSize {
            out += try stream.push(Array(buf[offset..<offset + decryptedChunkSize]), tag: .message)
            offset += decryptedChunkSize
        }
        buf.removeFirst(offset)
        return out
    }

    /// Emits the final frame and marks the encryptor as finished.
    public mutating func finish() throws -> [UInt8] {
        guard !finished else {
            throw XChatError.invalidInput("File encryptor already finished")
        }
        finished = true
        var out = prefix
        prefix = []
        if started {
            out += try stream.push(buf, tag: .final)
            buf = []
        }
        return out
    }
}

/// Ways a stream fails to decrypt.
private enum StreamFault {
    /// A frame followed by more data failed to authenticate.
    case badFrame
    /// The last frame failed to authenticate, so it may also be cut short.
    case badLastFrame
    /// Data follows the final frame.
    case trailingData
    /// The input ended inside the header.
    case truncatedHeader
    /// The input ended before the final frame.
    case truncated
}

/// Incremental decryptor for one encrypted file.
///
/// Feed ciphertext with `push` and call `finish` once at end of input. Each
/// chunk fed to `push` is authenticated as it is decrypted, but the file is
/// only proven complete when `finish` returns: a file that ends before its
/// final frame is rejected as truncated, so callers must not treat plaintext
/// from `push` as complete until `finish` succeeds.
///
/// Input may be split across `push` calls at any byte boundary; frames are
/// reassembled internally.
public struct FileDecryptor {
    /// Stream key, held until the header is complete.
    private let key: [UInt8]
    /// Underlying secretstream puller; nil until the header is consumed.
    private var pull: SecretStreamPull?
    /// Header bytes accumulated until the 24-byte header is complete.
    private var header: [UInt8]
    /// Ciphertext held until a full frame is available; at most one frame.
    private var buf: [UInt8]
    /// Whether any frame has been decrypted.
    private var sawChunk: Bool
    /// Whether the final frame has been decrypted.
    private var sawFinal: Bool
    /// Media hash key of the file being decrypted, named in errors.
    private let mediaHashKey: String?
    /// Set by `finish`, which consumes the decryptor in the reference API.
    private var finished: Bool

    /// Creates a decryptor for one file under a 32-byte conversation key.
    public init(key: [UInt8]) throws {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        self.init(validatedKey: key, mediaHashKey: nil)
    }

    /// Creates a decryptor for the media file named by `mediaHashKey`,
    /// whose errors name that media and say what to pass instead.
    public init(key: [UInt8], mediaHashKey: String) throws {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        self.init(validatedKey: key, mediaHashKey: mediaHashKey)
    }

    private init(validatedKey: [UInt8], mediaHashKey: String?) {
        key = validatedKey
        pull = nil
        header = []
        buf = []
        sawChunk = false
        sawFinal = false
        self.mediaHashKey = mediaHashKey
        finished = false
    }

    private func fault(_ fault: StreamFault) -> XChatError {
        guard let hashKey = mediaHashKey else {
            switch fault {
            case .badFrame, .badLastFrame:
                return XChatError.decryption("secretstream pull failed")
            case .trailingData:
                return XChatError.decryption("data after final stream frame")
            case .truncatedHeader:
                return XChatError.decryption("stream ended before header was complete")
            case .truncated:
                return XChatError.decryption("stream truncated: ended before final frame")
            }
        }
        switch fault {
        case .badFrame:
            return XChatError.decryption(
                "the bytes are not the encrypted file of media_hash_key '\(hashKey)', or they "
                    + "are corrupted: pass the bytes downloaded for that media hash key")
        case .badLastFrame:
            return XChatError.decryption(
                "the bytes are not the complete encrypted file of media_hash_key '\(hashKey)': "
                    + "they are truncated, corrupted, or another file; pass the complete bytes "
                    + "downloaded for that media hash key")
        case .trailingData:
            return XChatError.decryption(
                "the bytes continue past the end of the encrypted file of media_hash_key "
                    + "'\(hashKey)': pass only the bytes downloaded for that media hash key")
        case .truncatedHeader, .truncated:
            return XChatError.decryption(
                "the bytes of media_hash_key '\(hashKey)' are truncated: pass the complete bytes "
                    + "downloaded for that media hash key")
        }
    }

    /// Pulls `frame` through the stored stream, in place. The stream must
    /// have been initialized by a previous `push`. Optional chaining is the
    /// in-place equivalent of the reference's mutable borrow: the stream's
    /// advance survives even when the surrounding call later throws.
    private mutating func pullFrame(
        _ frame: [UInt8]
    ) throws -> (plaintext: [UInt8], tag: SecretStreamTag) {
        guard let pulled = try pull?.pull(frame) else {
            preconditionFailure("pull initialized above")
        }
        return pulled
    }

    /// Decrypts a ciphertext chunk, returning the plaintext recoverable so
    /// far. The final frame is held back for `finish`, so the returned
    /// bytes may be empty until enough input has arrived.
    public mutating func push(_ ciphertext: [UInt8]) throws -> [UInt8] {
        guard !finished else {
            throw XChatError.invalidInput("File decryptor already finished")
        }
        if sawFinal {
            throw fault(.trailingData)
        }
        var input = ciphertext[...]

        // Consume the header before any frame can be pulled.
        if pull == nil {
            let need = streamHeaderSize - header.count
            let take = min(need, input.count)
            header += input.prefix(take)
            input = input.dropFirst(take)
            if header.count < streamHeaderSize {
                return []
            }
            pull = try SecretStreamPull(header: header, key: key)
        }

        buf += input

        // While more than one full frame is buffered, the leading frame has
        // data after it and so must be a non-final message frame.
        var out: [UInt8] = []
        var offset = 0
        while buf.count - offset > encryptedChunkSize {
            let frame = Array(buf[offset..<offset + encryptedChunkSize])
            offset += encryptedChunkSize
            let (framePlaintext, tag): ([UInt8], SecretStreamTag)
            do {
                (framePlaintext, tag) = try pullFrame(frame)
            } catch {
                throw fault(.badFrame)
            }
            sawChunk = true
            out += framePlaintext
            if tag == .final {
                throw fault(.trailingData)
            }
        }
        buf.removeFirst(offset)
        return out
    }

    /// Decrypts the final frame and consumes the decryptor. Throws if the
    /// file ended before its final frame, which detects truncation. A file
    /// of only the 24-byte header decrypts to empty output.
    public mutating func finish() throws -> [UInt8] {
        guard !finished else {
            throw XChatError.invalidInput("File decryptor already finished")
        }
        finished = true
        guard pull != nil else {
            throw fault(.truncatedHeader)
        }

        var out: [UInt8] = []
        if !buf.isEmpty {
            let frame = buf
            buf = []
            let (framePlaintext, tag): ([UInt8], SecretStreamTag)
            do {
                (framePlaintext, tag) = try pullFrame(frame)
            } catch {
                throw fault(.badLastFrame)
            }
            sawChunk = true
            out += framePlaintext
            if tag == .final {
                sawFinal = true
            }
        }

        if sawChunk && !sawFinal {
            throw fault(.truncated)
        }
        return out
    }
}

/// Encrypts a whole file: the concatenated output of feeding `plaintext`
/// through a `FileEncryptor` in 1024-byte chunks.
func encryptFile(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
    var encryptor = try FileEncryptor(key: key)
    var out: [UInt8] = []
    var offset = 0
    while offset < plaintext.count {
        let end = min(offset + decryptedChunkSize, plaintext.count)
        out += try encryptor.push(Array(plaintext[offset..<end]))
        offset = end
    }
    out += try encryptor.finish()
    return out
}

/// Decrypts a whole encrypted file, rejecting truncated ones.
func decryptFile(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
    var decryptor = try FileDecryptor(key: key)
    var out: [UInt8] = []
    var offset = 0
    while offset < ciphertext.count {
        let end = min(offset + encryptedChunkSize, ciphertext.count)
        out += try decryptor.push(Array(ciphertext[offset..<end]))
        offset = end
    }
    out += try decryptor.finish()
    return out
}

/// Decrypts the whole encrypted media file named by `mediaHashKey`; its
/// errors name that media and say what to pass instead.
func decryptMedia(key: [UInt8], mediaHashKey: String, encrypted: [UInt8]) throws -> [UInt8] {
    var decryptor = try FileDecryptor(key: key, mediaHashKey: mediaHashKey)
    var out: [UInt8] = []
    var offset = 0
    while offset < encrypted.count {
        let end = min(offset + encryptedChunkSize, encrypted.count)
        out += try decryptor.push(Array(encrypted[offset..<end]))
        offset = end
    }
    out += try decryptor.finish()
    return out
}
