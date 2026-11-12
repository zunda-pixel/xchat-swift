# Juicebox recovery in Swift

Tweetbot's DM notification previews recover the account's X Chat private
keys from Juicebox with the user's DM passcode. The Rust `juicebox_sdk`
did that inside chat-xdk; this target ports the **recovery** path to Swift
so the app can drop the Rust build.

The target is a driver: the **app performs the realm HTTP requests** and
the target does the cryptography, mirroring the SDK's no-networking rule.

## Implemented

- `Blake2s` (RFC 7693), `hmacBlake2s`, `hkdfBlake2s`.
- `NoiseNK`: the client side of `Noise_NK_25519_ChaChaPoly_BLAKE2s`, the
  channel Juicebox hardware realms speak (handshake plus transport),
  built on swift-crypto's X25519 and ChaChaPoly.
- Tests: BLAKE2s RFC vectors; Noise NK against the official Noise test
  vectors (`Tests/JuiceboxTests/Fixtures/noise_nk_vectors.json`), checking
  handshake messages and transport frames byte for byte.

## Protocol (from `juicebox-sdk@0.3.7`)

Three phases per realm, at most `recover_threshold` of `realms` needed:

1. `Recover1` → the registration `version` (16 bytes), or NotRegistered /
   NoGuesses.
2. **PIN hash**: Argon2id, version 0x13, `m_cost = 16384`, `t_cost = 32`,
   `p_cost = 1`, 64 bytes, with salt
   `be32(len(version)) ‖ version ‖ be32(len(info)) ‖ info` and empty
   `UserInfo`. Output: `access_key` (32) ‖ `encryption_key_seed` (32).
   There is a fixed vector in the reference source.
3. **OPRF** (Ristretto255 over SHA-512):
   - `start`: `input_point = hash_to_group(access_key)`,
     `blinding = random Scalar`, send `input_point · blinding`.
   - Each realm answers `oprf_blinded_result` (RistrettoPoint),
     `oprf_signed_public_key`, a DLEQ `proof`, `unlock_key_commitment`,
     `num_guesses`, `guess_count`. Verify the realm's signed public key
     and the proof.
   - Combine the result shares with Shamir interpolation, unblind
     (`· blinding⁻¹`), `hash_to_output` = SHA-512(`"Juicebox_OPRF_2023_1;" ‖
     input ‖ compressed result`), derive `unlock_key` and
     `unlock_key_commitment`; a mismatch means a wrong PIN.
4. `Recover3` with `unlock_key_tag = UnlockKeyTag(unlock_key, realm id)`
   → an `encryption_key_scalar_share`, the `encrypted_secret`, and its
   commitment. Check each share's commitment, combine the scalar shares,
   derive `encryption_key = HKDF(encryption_key_seed, scalar)` and decrypt
   the secret (the 64 private-key bytes).

Wire format: software realms take JSON with `Authorization: Bearer <token>`;
hardware realms (those with a `public_key`) take marshalled requests over
Noise. The X Chat config carries realm public keys, so both paths matter.

Secret sharing is Shamir over `Scalar`/`RistrettoPoint`, indices `1...n` as
scalars, Lagrange interpolation with the secret as the constant term.

## Remaining

1. **Argon2id** with the reference parameters (RFC 9106 vectors, plus the
   reference PIN vector).
2. **Ristretto255 + Scalar** and the **OPRF with DLEQ**, with RFC 9496 and
   reference vectors. This is the largest piece; the dependency choice
   (hand-port vs. a vetted library) is open.
3. **Secret sharing** and **marshalling**.
4. **Realm API** request/response types, signed OPRF public keys, padded
   responses.
5. **Recovery driver**: the three phases, thresholds, retries, session
   reuse, error mapping (`InvalidPin { guesses_remaining }`, …), with the
   app performing HTTP.
6. **Tweetbot**: replace `XChatKeyRecovery` and remove chat-xdk.
