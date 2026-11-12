/// Argon2id (version 19, RFC 9106), the PIN stretching Juicebox recovery
/// uses. Implemented single threaded with the reference implementation's
/// exact block layout and indexing.
struct Argon2 {
    /// A memory block is 1024 bytes, 128 64-bit words.
    static let blockWords = 128
    static let syncPoints = 4
    static let addressesInBlock = 128
    static let version: UInt32 = 0x13
    /// Argon2id's algorithm identifier in the initial hash.
    static let algorithmID: UInt32 = 2

    /// Derives `outputLength` bytes from `password` under `salt`, with the
    /// memory, pass, and lane counts given.
    static func id(
        password: [UInt8],
        salt: [UInt8],
        secret: [UInt8] = [],
        associatedData: [UInt8] = [],
        memoryCost: UInt32,
        timeCost: UInt32,
        parallelism: UInt32,
        outputLength: Int
    ) -> [UInt8] {
        precondition(outputLength >= 4, "Argon2 output is at least 4 bytes")
        precondition(salt.count >= 8, "Argon2 salt is at least 8 bytes")
        precondition(timeCost >= 1, "Argon2 needs at least one pass")
        precondition(parallelism >= 1, "Argon2 needs at least one lane")
        precondition(
            memoryCost >= 8 * parallelism, "Argon2 needs 8 blocks per lane")

        let lanes = Int(parallelism)
        let segmentLength = Int(max(memoryCost, UInt32(8 * lanes))) / (lanes * syncPoints)
        let laneLength = segmentLength * syncPoints
        let blockCount = laneLength * lanes

        let initialHash = initialHash(
            password: password, salt: salt, secret: secret,
            associatedData: associatedData, memoryCost: memoryCost,
            timeCost: timeCost, parallelism: parallelism, outputLength: outputLength)

        var memory = [UInt64](repeating: 0, count: blockCount * blockWords)
        for lane in 0..<lanes {
            for index in 0..<2 {
                var input = initialHash
                input += le32(UInt32(index))
                input += le32(UInt32(lane))
                writeBlock(
                    &memory, lane * laneLength + index,
                    words(from: blake2bLong(input, length: 1024)))
            }
        }

        for pass in 0..<Int(timeCost) {
            for slice in 0..<syncPoints {
                let dataIndependent = pass == 0 && slice < syncPoints / 2
                for lane in 0..<lanes {
                    var addressBlock = [UInt64](repeating: 0, count: blockWords)
                    var inputBlock = [UInt64](repeating: 0, count: blockWords)
                    let zeroBlock = [UInt64](repeating: 0, count: blockWords)
                    if dataIndependent {
                        inputBlock[0] = UInt64(pass)
                        inputBlock[1] = UInt64(lane)
                        inputBlock[2] = UInt64(slice)
                        inputBlock[3] = UInt64(blockCount)
                        inputBlock[4] = UInt64(timeCost)
                        inputBlock[5] = UInt64(algorithmID)
                    }

                    let firstBlock = (pass == 0 && slice == 0) ? 2 : 0
                    if pass == 0 && slice == 0 && dataIndependent {
                        updateAddressBlock(&addressBlock, &inputBlock, zeroBlock)
                    }

                    var currentIndex = lane * laneLength + slice * segmentLength + firstBlock
                    var previousIndex =
                        (slice == 0 && firstBlock == 0)
                        ? currentIndex + laneLength - 1
                        : currentIndex - 1

                    for block in firstBlock..<segmentLength {
                        let random: UInt64
                        if dataIndependent {
                            let addressIndex = block % addressesInBlock
                            if addressIndex == 0 {
                                updateAddressBlock(&addressBlock, &inputBlock, zeroBlock)
                            }
                            random = addressBlock[addressIndex]
                        } else {
                            random = memory[previousIndex * blockWords]
                        }

                        let referenceLane =
                            (pass == 0 && slice == 0)
                            ? lane
                            : Int((random >> 32) % UInt64(lanes))

                        let referenceAreaSize: Int
                        if pass == 0 {
                            if slice == 0 {
                                referenceAreaSize = block - 1
                            } else if referenceLane == lane {
                                referenceAreaSize = slice * segmentLength + block - 1
                            } else {
                                referenceAreaSize = slice * segmentLength - (block == 0 ? 1 : 0)
                            }
                        } else {
                            if referenceLane == lane {
                                referenceAreaSize =
                                    laneLength - segmentLength + block - 1
                            } else {
                                referenceAreaSize =
                                    laneLength - segmentLength - (block == 0 ? 1 : 0)
                            }
                        }

                        var map = random & 0xFFFF_FFFF
                        map = (map &* map) >> 32
                        let relativePosition =
                            referenceAreaSize - 1
                            - Int((UInt64(referenceAreaSize) &* map) >> 32)
                        let startPosition =
                            (pass != 0 && slice != syncPoints - 1)
                            ? (slice + 1) * segmentLength
                            : 0
                        let laneIndex = (startPosition + relativePosition) % laneLength
                        let referenceIndex = referenceLane * laneLength + laneIndex

                        let result = compress(
                            readBlock(memory, previousIndex),
                            readBlock(memory, referenceIndex))
                        if pass == 0 {
                            writeBlock(&memory, currentIndex, result)
                        } else {
                            var updated = readBlock(memory, currentIndex)
                            for i in 0..<blockWords {
                                updated[i] ^= result[i]
                            }
                            writeBlock(&memory, currentIndex, updated)
                        }

                        previousIndex = currentIndex
                        currentIndex += 1
                    }
                }
            }
        }

        var last = readBlock(memory, laneLength - 1)
        for lane in 1..<lanes {
            let block = readBlock(memory, lane * laneLength + laneLength - 1)
            for i in 0..<blockWords {
                last[i] ^= block[i]
            }
        }
        return blake2bLong(bytes(from: last), length: outputLength)
    }

    // MARK: Initial hash

    private static func initialHash(
        password: [UInt8],
        salt: [UInt8],
        secret: [UInt8],
        associatedData: [UInt8],
        memoryCost: UInt32,
        timeCost: UInt32,
        parallelism: UInt32,
        outputLength: Int
    ) -> [UInt8] {
        var data: [UInt8] = []
        data += le32(parallelism)
        data += le32(UInt32(outputLength))
        data += le32(memoryCost)
        data += le32(timeCost)
        data += le32(version)
        data += le32(algorithmID)
        appendLengthPrefixed(&data, password)
        appendLengthPrefixed(&data, salt)
        appendLengthPrefixed(&data, secret)
        appendLengthPrefixed(&data, associatedData)
        return Blake2b.hash(data, outputLength: 64)
    }

    private static func appendLengthPrefixed(_ data: inout [UInt8], _ value: [UInt8]) {
        data += le32(UInt32(value.count))
        data += value
    }

    // MARK: Compression

    private static func updateAddressBlock(
        _ addressBlock: inout [UInt64],
        _ inputBlock: inout [UInt64],
        _ zeroBlock: [UInt64]
    ) {
        inputBlock[6] &+= 1
        addressBlock = compress(zeroBlock, inputBlock)
        addressBlock = compress(zeroBlock, addressBlock)
    }

    /// `G(x, y)`: XOR the blocks, permute rows then columns, XOR the XOR back.
    private static func compress(_ x: [UInt64], _ y: [UInt64]) -> [UInt64] {
        var r = [UInt64](repeating: 0, count: blockWords)
        for i in 0..<blockWords {
            r[i] = x[i] ^ y[i]
        }
        var q = r
        for chunk in 0..<8 {
            let b = chunk * 16
            permute(
                &q,
                b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15)
        }
        for i in 0..<8 {
            let b = i * 2
            permute(
                &q,
                b, b + 1,
                b + 16, b + 17,
                b + 32, b + 33,
                b + 48, b + 49,
                b + 64, b + 65,
                b + 80, b + 81,
                b + 96, b + 97,
                b + 112, b + 113)
        }
        for i in 0..<blockWords {
            q[i] ^= r[i]
        }
        return q
    }

    private static func permute(
        _ v: inout [UInt64],
        _ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int,
        _ i4: Int, _ i5: Int, _ i6: Int, _ i7: Int,
        _ i8: Int, _ i9: Int, _ i10: Int, _ i11: Int,
        _ i12: Int, _ i13: Int, _ i14: Int, _ i15: Int
    ) {
        step(&v, i0, i4, i8, i12)
        step(&v, i1, i5, i9, i13)
        step(&v, i2, i6, i10, i14)
        step(&v, i3, i7, i11, i15)
        step(&v, i0, i5, i10, i15)
        step(&v, i1, i6, i11, i12)
        step(&v, i2, i7, i8, i13)
        step(&v, i3, i4, i9, i14)
    }

    private static func step(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFF_FFFF) &* (v[b] & 0xFFFF_FFFF)
        v[d] = (v[d] ^ v[a]).rotatedRight(32)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFF_FFFF) &* (v[d] & 0xFFFF_FFFF)
        v[b] = (v[b] ^ v[c]).rotatedRight(24)

        v[a] = v[a] &+ v[b] &+ 2 &* (v[a] & 0xFFFF_FFFF) &* (v[b] & 0xFFFF_FFFF)
        v[d] = (v[d] ^ v[a]).rotatedRight(16)
        v[c] = v[c] &+ v[d] &+ 2 &* (v[c] & 0xFFFF_FFFF) &* (v[d] & 0xFFFF_FFFF)
        v[b] = (v[b] ^ v[c]).rotatedRight(63)
    }

    // MARK: Block helpers

    private static func readBlock(_ memory: [UInt64], _ index: Int) -> [UInt64] {
        Array(memory[(index * blockWords)..<(index * blockWords + blockWords)])
    }

    private static func writeBlock(_ memory: inout [UInt64], _ index: Int, _ block: [UInt64]) {
        memory.replaceSubrange(
            (index * blockWords)..<(index * blockWords + blockWords), with: block)
    }

    private static func words(from bytes: [UInt8]) -> [UInt64] {
        var words = [UInt64](repeating: 0, count: blockWords)
        for i in 0..<blockWords {
            var value: UInt64 = 0
            for j in 0..<8 {
                value |= UInt64(bytes[i * 8 + j]) << (8 * UInt64(j))
            }
            words[i] = value
        }
        return words
    }

    private static func bytes(from words: [UInt64]) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(blockWords * 8)
        for word in words {
            bytes += word.leBytes
        }
        return bytes
    }
}

private func le32(_ value: UInt32) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: value),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 24),
    ]
}
