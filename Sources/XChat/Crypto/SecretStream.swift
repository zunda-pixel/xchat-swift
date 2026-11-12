/// The frame tag secretstream attaches to every frame, which pull returns
/// to the caller and which `rekey` uses to rotate the key mid-stream.
enum SecretStreamTag: UInt8, Sendable {
    /// Most common tag; carries no extra meaning.
    case message = 0
    /// Marks the end of a set of messages, not the end of the stream.
    case push = 1
    /// Rotates the stream key after this frame.
    case rekey = 2
    /// Marks the end of the stream.
    case final = 3
}

/// `crypto_secretstream_xchacha20poly1305` — the streaming AEAD media files
/// are encrypted with. Ported frame-for-frame from the reference
/// implementation the wire format is frozen against (libsodium's layout):
/// a 24-byte header of random bytes, per-frame nonces derived from a
/// counter and a MAC-chained nonce, and a Poly1305 tag computed over the
/// encrypted frame tag block, the ciphertext, and a libsodium-specific
/// padding quirk.
private struct SecretStreamState: Sendable {
    /// Stream key after HChaCha20 subkey derivation.
    private var key: [UInt8]
    /// Eight bytes of the header, chained into each frame's nonce.
    private var nonce: [UInt8]
    /// Frame counter; the first frame is 1.
    private var counter: UInt32

    init(key: [UInt8], header: [UInt8]) {
        precondition(key.count == 32, "secretstream keys are 32 bytes")
        precondition(header.count == 24, "secretstream headers are 24 bytes")
        // The first 16 header bytes derive the subkey; the last 8 are the
        // starting nonce.
        self.key = hchacha20(key: key, input: Array(header[0..<16]))
        self.nonce = Array(header[16..<24])
        self.counter = 1
    }

    /// The per-frame 12-byte ChaCha20 nonce: counter ‖ chained nonce.
    var cipherNonce: [UInt8] {
        counter.leBytes + nonce
    }

    /// A cipher for the current frame plus its Poly1305 one-time key, which
    /// is the first 32 keystream bytes.
    private func cipherAndMacKey(cipherNonce: [UInt8]) -> (ChaCha20, [UInt8]) {
        var cipher = ChaCha20(key: key, nonce: cipherNonce)
        var macKey = [UInt8](repeating: 0, count: 32)
        cipher.xor(into: &macKey)
        return (cipher, macKey)
    }

    /// XORs the nonce with the frame's MAC, increments the counter, and
    /// rekeys when asked or when the counter wraps.
    mutating func updateState(macOutput: [UInt8], tag: SecretStreamTag) {
        for i in 0..<8 {
            nonce[i] ^= macOutput[i]
        }

        let (incremented, overflow) = counter.addingReportingOverflow(1)
        if !overflow && tag != .rekey {
            counter = incremented
        } else {
            counter = incremented
            rekey()
        }
    }

    /// Rotates the key and nonce with the keystream of the current frame's
    /// cipher, and restarts the counter.
    private mutating func rekey() {
        var cipher = ChaCha20(key: key, nonce: cipherNonce)
        cipher.xor(into: &key)
        cipher.xor(into: &nonce)
        counter = 1
    }

    /// The Poly1305 MAC over the encrypted frame: the associated data, the
    /// encrypted 64-byte tag block, the ciphertext's full blocks, and a
    /// final segment holding the ciphertext tail, libsodium's padding error
    /// bytes, and a size block.
    private func computeMac(
        macKey: [UInt8],
        associatedData: [UInt8],
        tagBlock: [UInt8],
        ciphertext: ArraySlice<UInt8>
    ) -> [UInt8] {
        var mac = Poly1305(key: macKey)

        // The number of padding bytes libsodium inserts before the size
        // block — a quirk of its block layout that the wire format keeps.
        let macPaddingErrorSize = (0x10 - 64 + ciphertext.count) & 0xf

        var sizeBlock = [UInt8](repeating: 0, count: 16)
        sizeBlock.replaceSubrange(0..<8, with: UInt64(associatedData.count).leBytes)
        sizeBlock.replaceSubrange(8..<16, with: UInt64(64 + ciphertext.count).leBytes)

        mac.updatePadded(associatedData)
        mac.updatePadded(tagBlock)

        // The slice's indices start where the ciphertext does, not at zero.
        let base = ciphertext.startIndex
        let fullBlockCount = ciphertext.count / 16
        for i in 0..<fullBlockCount {
            mac.processBlock(
                ciphertext[(base + i * 16)..<(base + (i + 1) * 16)], partial: false)
        }

        var lastBlocks = [UInt8](repeating: 0, count: 48)
        let remainder = ciphertext[(base + fullBlockCount * 16)...]
        lastBlocks.replaceSubrange(0..<remainder.count, with: remainder)
        let sizeBlockOffset = remainder.count + macPaddingErrorSize
        lastBlocks.replaceSubrange(sizeBlockOffset..<(sizeBlockOffset + 16), with: sizeBlock)

        return mac.computeUnpadded(Array(lastBlocks[0..<(sizeBlockOffset + 16)]))
    }

    /// Encrypts `buffer` — the frame tag byte followed by the message — in
    /// place, returning the frame MAC. `cipherNonce` is the current frame's
    /// nonce.
    mutating func encryptFrame(
        cipherNonce: [UInt8],
        associatedData: [UInt8],
        buffer: inout [UInt8]
    ) -> [UInt8] {
        let (prepared, macKey) = cipherAndMacKey(cipherNonce: cipherNonce)
        var cipher = prepared

        // The tag block: the tag byte in an otherwise zero 64-byte block,
        // encrypted from keystream block 1.
        var tagBlock = [UInt8](repeating: 0, count: 64)
        tagBlock[0] = buffer[0]
        cipher.seek(to: 64)
        cipher.xor(into: &tagBlock)
        buffer[0] = tagBlock[0]

        // The message, encrypted from keystream block 2.
        cipher.seek(to: 128)
        cipher.xor(into: &buffer, range: 1..<buffer.count)

        return computeMac(
            macKey: macKey,
            associatedData: associatedData,
            tagBlock: tagBlock,
            ciphertext: buffer[1...])
    }

    /// Verifies `mac` over the encrypted frame in `buffer` — the encrypted
    /// tag byte followed by the ciphertext — then decrypts it in place,
    /// leaving the decrypted tag byte at `buffer[0]`.
    mutating func decryptFrame(
        cipherNonce: [UInt8],
        associatedData: [UInt8],
        buffer: inout [UInt8],
        mac: [UInt8]
    ) throws {
        let (prepared, macKey) = cipherAndMacKey(cipherNonce: cipherNonce)
        var cipher = prepared

        var tagBlock = [UInt8](repeating: 0, count: 64)
        tagBlock[0] = buffer[0]
        cipher.seek(to: 64)
        cipher.xor(into: &tagBlock)
        // After the swap, buffer[0] holds the decrypted tag byte and
        // tagBlock[0] the encrypted one the MAC was computed over.
        swap(&tagBlock[0], &buffer[0])

        let macOutput = computeMac(
            macKey: macKey,
            associatedData: associatedData,
            tagBlock: tagBlock,
            ciphertext: buffer[1...])
        guard constantTimeEquals(macOutput, mac) else {
            throw XChatError.decryption("secretstream pull failed")
        }

        cipher.seek(to: 128)
        cipher.xor(into: &buffer, range: 1..<buffer.count)
    }
}

/// The sending side of a secretstream: encrypts framed messages under a
/// shared key, emitting a random 24-byte header first.
struct SecretStreamPush {
    private var state: SecretStreamState

    /// Starts a stream under a 32-byte key, returning the cleartext header
    /// to prepend to the frames and the pusher itself.
    static func start(key: [UInt8]) throws -> (header: [UInt8], stream: SecretStreamPush) {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        var header = [UInt8](repeating: 0, count: 24)
        for i in header.indices {
            header[i] = UInt8.random(in: 0...255)
        }
        return (header, SecretStreamPush(state: SecretStreamState(key: key, header: header)))
    }

    private init(state: SecretStreamState) {
        self.state = state
    }

    /// Encrypts one message into a frame of 17 + message bytes, carrying
    /// `tag`; the stream advances its nonce chain.
    mutating func push(
        _ plaintext: [UInt8],
        associatedData: [UInt8] = [],
        tag: SecretStreamTag
    ) -> [UInt8] {
        let cipherNonce = state.cipherNonce
        var buffer = [tag.rawValue] + plaintext
        let mac = state.encryptFrame(
            cipherNonce: cipherNonce, associatedData: associatedData, buffer: &buffer)
        state.updateState(macOutput: mac, tag: tag)
        return buffer + mac
    }
}

/// The receiving side of a secretstream: verifies and decrypts the frames a
/// `SecretStreamPush` produced, given the header and the shared key.
struct SecretStreamPull {
    private var state: SecretStreamState

    init(header: [UInt8], key: [UInt8]) throws {
        guard key.count == 32 else {
            throw XChatError.invalidInput("Conversation key must be 32 bytes")
        }
        guard header.count == 24 else {
            throw XChatError.invalidInput("secretstream headers are 24 bytes")
        }
        self.state = SecretStreamState(key: key, header: header)
    }

    /// Verifies and decrypts one frame, returning its message and tag; the
    /// stream advances its nonce chain. A frame that fails verification
    /// throws without yielding plaintext.
    mutating func pull(
        _ frame: [UInt8],
        associatedData: [UInt8] = []
    ) throws -> (plaintext: [UInt8], tag: SecretStreamTag) {
        let cipherNonce = state.cipherNonce

        guard frame.count >= 17 else {
            throw XChatError.decryption("secretstream pull failed")
        }
        let mac = Array(frame.suffix(16))
        var buffer = Array(frame[0..<(frame.count - 16)])
        try state.decryptFrame(
            cipherNonce: cipherNonce, associatedData: associatedData, buffer: &buffer, mac: mac)

        guard let tag = SecretStreamTag(rawValue: buffer[0]) else {
            throw XChatError.decryption("secretstream pull failed")
        }
        let plaintext = Array(buffer[1...])
        state.updateState(macOutput: mac, tag: tag)
        return (plaintext, tag)
    }
}
