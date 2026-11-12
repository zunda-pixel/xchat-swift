/// Juicebox's PIN stretching: Argon2id with a salt built from the
/// registration version and user info, producing the OPRF access key and the
/// seed that encrypts the recovered user secret.
func juiceboxPinHash(
    pin: [UInt8],
    registrationVersion: [UInt8],
    userInfo: [UInt8] = [],
    mode: JuiceboxPinHashingMode = .standard2019
) -> (accessKey: [UInt8], encryptionKeySeed: [UInt8]) {
    var salt: [UInt8] = []
    salt += be32(UInt32(registrationVersion.count))
    salt += registrationVersion
    salt += be32(UInt32(userInfo.count))
    salt += userInfo

    let parameters = mode.parameters
    let hashed = Argon2.id(
        password: pin, salt: salt,
        memoryCost: parameters.memory, timeCost: parameters.time,
        parallelism: parameters.parallelism,
        outputLength: 64)
    return (Array(hashed[0..<32]), Array(hashed[32..<64]))
}
