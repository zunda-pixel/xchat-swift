/// Juicebox's `Standard2019` PIN stretching: Argon2id with a salt built from
/// the registration version and user info, producing the OPRF access key and
/// the seed that encrypts the recovered user secret.
func juiceboxPinHash(
    pin: [UInt8],
    registrationVersion: [UInt8],
    userInfo: [UInt8] = []
) -> (accessKey: [UInt8], encryptionKeySeed: [UInt8]) {
    var salt: [UInt8] = []
    salt += be32(UInt32(registrationVersion.count))
    salt += registrationVersion
    salt += be32(UInt32(userInfo.count))
    salt += userInfo

    let hashed = Argon2.id(
        password: pin, salt: salt,
        memoryCost: 16 * 1024, timeCost: 32, parallelism: 1,
        outputLength: 64)
    return (Array(hashed[0..<32]), Array(hashed[32..<64]))
}
