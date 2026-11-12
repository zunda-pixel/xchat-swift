import Crypto

struct AES128GCM {
    private let key: SymmetricKey

    init(key: [UInt8]) {
        precondition(key.count == 16)
        self.key = SymmetricKey(data: key)
    }

    func seal(
        nonce: [UInt8], plaintext: [UInt8], authenticatedData: [UInt8] = []
    ) throws -> [UInt8] {
        let box = try AES.GCM.seal(
            plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce),
            authenticating: authenticatedData)
        return Array(box.ciphertext) + Array(box.tag)
    }

    func open(
        nonce: [UInt8], ciphertextAndTag: [UInt8], authenticatedData: [UInt8] = []
    ) throws -> [UInt8] {
        let tagSize = 16
        guard ciphertextAndTag.count >= tagSize else {
            throw XChatError.decryption("Ciphertext too short")
        }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertextAndTag.dropLast(tagSize),
            tag: ciphertextAndTag.suffix(tagSize))
        return try Array(AES.GCM.open(box, using: key, authenticating: authenticatedData))
    }
}
