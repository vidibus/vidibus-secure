# Changelog

## 5.0.0

Major release.

### Breaking

- Cipher changed from AES-256-CBC to **AES-256-GCM** with a
  random 96-bit IV and 128-bit auth tag per encryption.
- New binary storage layout (then base64- or hex-encoded as
  before):

  ```
  [1-byte version = 0x02][12-byte IV][16-byte tag][ciphertext]
  ```

- Key derivation: `pkcs5_keyivgen` is gone. The key passed
  to `encrypt`/`decrypt` IS the AES key (32 bytes). If a
  shorter or longer key is supplied, it is reduced to 32
  bytes via `SHA256(key)`.

### Backward compatibility

- v4 ciphertexts (bare base64, no version byte) and any
  blob prefixed with the reserved `0x01` version byte
  continue to decrypt via a legacy CBC path. New writes
  always emit `0x02`.
- To re-encrypt at rest into the new format, iterate your
  records and reassign each encrypted attribute — the
  getter/setter cycle moves the value to GCM.

### Added

- `Vidibus::Secure.legacy_decrypt(data, key, options = {})` —
  forces the v4 CBC path. Use only for the rare case where a
  legacy blob's first byte collides with `0x01`/`0x02` and is
  misrouted by the version-byte dispatch.
- `Vidibus::Secure.key_resolver` — module-level lambda
  accessor for per-call key resolution. Useful in
  multi-tenant setups where each request may need a
  different encryption key.
- `Vidibus::Secure.current_key` — resolver wins over
  `ENV["VIDIBUS_SECURE_KEY"]`; raises `KeyError` if
  neither is set.
- `Vidibus::Secure::DecryptError` — raised on tampered
  ciphertext (GCM auth tag verification failure) instead
  of returning garbage. Authenticated decryption is the
  whole point of the GCM switch.

### Mongoid

- `attr_encrypted` no longer captures `ENV` at class-load
  time. The key is resolved on every read and write via
  `Vidibus::Secure.current_key`. Implementation switched
  from `class_eval` strings to `define_method`.

### Out of scope

- Request signing (`sign`, `sign_request`,
  `verify_request`) is unchanged.
