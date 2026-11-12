import XCTest

@testable import XChat

/// Poly1305 against RFC 8439: the §2.5.2 example and every A.3 vector,
/// including the partial-reduction edge cases #5–#11 that exercise the
/// donna limb arithmetic specifically.
final class Poly1305Tests: XCTestCase {
    private func hex(_ string: String) -> [UInt8] {
        try! Hex.decode(string)
    }

    private func tag(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var poly = Poly1305(key: key)
        return poly.computeUnpadded(data)
    }

    func testRFC8439Section252() {
        let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        let text = Array("Cryptographic Forum Research Group".utf8)
        XCTAssertEqual(tag(key: key, data: text), hex("a8061dc1305136c6c22b8baf0c0127a9"))
    }

    func testRFC8439AppendixA3() {
        let ietfText = Array(
            """
            Any submission to the IETF intended by the Contributor for publication \
            as all or part of an IETF Internet-Draft or RFC and any statement made \
            within the context of an IETF activity is considered an "IETF \
            Contribution". Such statements include oral statements in IETF \
            sessions, as well as written and electronic communications made at \
            any time or place, which are addressed to
            """.utf8)

        let jabberwocky = hex(
            "2754776173206272696c6c69672c2061"
                + "6e642074686520736c6974687920746f"
                + "7665730a446964206779726520616e64"
                + "2067696d626c6520696e207468652077"
                + "6162653a0a416c6c206d696d73792077"
                + "6572652074686520626f726f676f7665"
                + "732c0a416e6420746865206d6f6d6520"
                + "7261746873206f757467726162652e")

        let vectors: [(name: String, key: String, data: [UInt8], tag: String)] = [
            // #1: zero key, zero text.
            ("1", "0000000000000000000000000000000000000000000000000000000000000000",
             [UInt8](repeating: 0, count: 64), "00000000000000000000000000000000"),
            // #2: r == 0, so the tag is s regardless of the text.
            ("2", "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
             ietfText, "36e5f6b5c5e06070f0efca96227a863e"),
            // #3: s == 0.
            ("3", "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
             ietfText, "f3477e7cd95417af89a6b8794c310cf0"),
            ("4", "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
             jabberwocky, "4541669a7eaaee61e708dc7cbcc5eb62"),
            // #5: partially reduced final result is not fully reduced.
            ("5", "0200000000000000000000000000000000000000000000000000000000000000",
             hex("ffffffffffffffffffffffffffffffff"), "03000000000000000000000000000000"),
            // #6: addition of s overflows modulo 2^128.
            ("6", "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
             hex("02000000000000000000000000000000"), "03000000000000000000000000000000"),
            // #7: data limb all ones plus carry from the lower limb.
            ("7", "0100000000000000000000000000000000000000000000000000000000000000",
             hex("ffffffffffffffffffffffffffffffff" + "f0ffffffffffffffffffffffffffffff"
                    + "11000000000000000000000000000000"),
             "05000000000000000000000000000000"),
            // #8: polynomial part is exactly 2^130 - 5.
            ("8", "0100000000000000000000000000000000000000000000000000000000000000",
             hex("ffffffffffffffffffffffffffffffff" + "fbfefefefefefefefefefefefefefefe"
                    + "01010101010101010101010101010101"),
             "00000000000000000000000000000000"),
            // #9: polynomial part is exactly 2^130 - 6.
            ("9", "0200000000000000000000000000000000000000000000000000000000000000",
             hex("fdffffffffffffffffffffffffffffff"), "faffffffffffffffffffffffffffffff"),
            // #10: 5*H+L-type reduction produces a 131-bit intermediate result.
            ("10", "01000000000000000400000000000000" + "00000000000000000000000000000000",
             hex("e33594d7505e43b90000000000000000" + "3394d7505e4379cd0100000000000000"
                    + "00000000000000000000000000000000" + "01000000000000000000000000000000"),
             "14000000000000005500000000000000"),
            // #11: 5*H+L-type reduction produces a 131-bit final result.
            ("11", "01000000000000000400000000000000" + "00000000000000000000000000000000",
             hex("e33594d7505e43b90000000000000000" + "3394d7505e4379cd0100000000000000"
                    + "00000000000000000000000000000000"),
             "13000000000000000000000000000000"),
        ]

        for vector in vectors {
            XCTAssertEqual(
                tag(key: hex(vector.key), data: vector.data),
                hex(vector.tag),
                "A.3 vector \(vector.name)"
            )
        }
    }

    /// Block-at-a-time feeding must equal one-shot feeding.
    func testIncrementalMatchesOneShot() {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let data = (0..<100).map { _ in UInt8.random(in: 0...255) }

        var incremental = Poly1305(key: key)
        let fullLength = data.count / 16 * 16
        var offset = 0
        while offset < fullLength {
            incremental.processBlock(data[offset..<offset + 16][...])
            offset += 16
        }
        let incrementalTag = incremental.computeUnpadded([UInt8](data[fullLength...]))

        XCTAssertEqual(incrementalTag, tag(key: key, data: data))
    }

    /// Empty input yields s mod 2^128 (the accumulator is zero).
    func testEmptyInput() {
        let key = hex("02000000000000000000000000000000ffffffffffffffffffffffffffffffff")
        XCTAssertEqual(tag(key: key, data: []), hex("ffffffffffffffffffffffffffffffff"))
    }
}
