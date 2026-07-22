# CLEP secrets

"CLEP" is Microsoft's own name for a family of device-binding blobs. It shows up in two unrelated places, which are easy to confuse:

- The obfuscated hardware-fingerprint blobs (`ClepV2`/`ClepV4`) sent as components `8196`/`8197` in the `deviceaddcredential.srf` request. See [Device](./device.md#deviceaddcredentialsrf) - they're just XOR/Feistel-obfuscated, not encrypted, and carry no key material.
- `ClepSignState` and `ClepHmacState`, documented below. These come back from the server as AES-encrypted secrets and are unrelated to the request blobs above beyond sharing a name and general shape.

## Shared encoding

`ClepSignState`, `ClepHmacState`, and `EncryptedDeviceKey` (see [Licenses](./licenses.md)) are all serialized the same way, as a fixed 4096-byte structure:

- `version: u32` - `4` for everything Xodus currently decodes
- `key_data` - the actual ciphertext, AES-128-CBC with a zero IV
- `key_schedule: [u32; 58]` - an expanded AES key schedule rather than a raw key

Xodus doesn't reconstruct the AES key from the schedule the "normal" way - it just reads the decryption key back out of four fixed offsets in `key_schedule` (`decryption_key` in `xodus/src/licensing/splicense.rs`). The same `decrypt_cbc_zero_iv` helper is reused for all three block types; only the size of `key_data` and which bytes of the decrypted plaintext are kept differ per type.

## ClepSignState

Lives inside the `SPLicenseBlock` returned by `deviceaddcredential.srf` (TLV block id `0x12d`). Its decrypted `key_data` is a 544-byte BCrypt RSA private key blob.

That key is the device's real credential. The random password sent in `Authentication/Password` during provisioning would still authenticate against `RST2.srf`, but a device token obtained that way isn't trusted enough to use against Xbox services - so the first `RST2.srf` request instead signs its body with this RSA key (`rsa-sha256`) to get a token that is. See [Device](./device.md#rst2srf).

## ClepHmacState

Same on-the-wire shape as `ClepSignState`, but a different source: it's the `<wst:BinarySecret>` ("proof token") returned alongside the device STS token in the `RequestSecurityTokenResponse` from the first `RST2.srf` call - it is not part of the `SPLicenseBlock`.

Its decrypted plaintext is a BCrypt key blob (a 12-byte header - magic/version/key size - followed by the raw key bytes). Xodus skips the header and takes the 32 raw key bytes that follow (`key_data[12..44]`) as the HMAC secret. The left-over bytes (`key_data[44..48]`) are padding. Every subsequent `RST2.srf` call made with the device token (`exchange_device_token`, `exchange_user_token`) derives per-request WS-SecureConversation keys from this secret using `SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED`, signs the request with HMAC-SHA256, and decrypts the response body with a key derived the same way.

## TPMInfo's role

`TPMInfo` is sent regardless of whether the device actually has a TPM - it's not gated on real TPM hardware. Its purpose is to hand the server an additional RSA key that adds another layer of security to later token exchanges, on top of `ClepHmacState`. Xodus omits `TPMInfo` entirely for now, for simplicity - see [Device](./device.md#deviceaddcredentialsrf).
