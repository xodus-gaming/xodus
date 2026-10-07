## Encryption

MSIXVC packages can be downloaded from Microsoft's CDN without the need for any
authentication because most of the package is encrypted.

The keys used to encrypt and decrypt the packages are called the Content
Integrity Keys (CIKs). CIKs are 32-byte keys identified by a unique UUID.
CIKs are not reused across packages. Microsoft's API returns a package's CIKs
only when the account has permission to decrypt that package.

Encryption information is stored in the `XVC Info` section. The XVC Info header
contains an array of encryption key UUIDs, where each one of the 192 key slots
is either the Nil UUID (all zeroes), or the UUID of a CIK. Then, each XVC
region contains a key ID field indicating the index of the CIK that encrypts
the region. If the XVC region is not encrypted, its key ID is `0xffff`. The
"Resident"[^1] regions must not be encrypted.

[^1]: See [layout](./msixvc.md#layout).

### Region Encryption

Each XVC region is encrypted independently using the XTS-AES (IEEE 1619-2007)
encryption mode with AES-128. XTS-AES requires two keys: a tweak key and a data
key. The CIK is therefore split into two halves: the first 16 bytes become the
tweak key, and the remaining 16 bytes become the data key.

Each page (4096 bytes) of the region is encrypted with a 16-byte `tweak`. Pages
are encrypted independently, meaning that any page of the region can be
decrypted by knowing its tweak and both keys. The tweak is calculated by
concatenating a 4-byte `data unit`, the 4-byte `region_id` of the XVC region,
and the first 8 bytes of the package's `vduid`. Both the data unit and the XVC
region ID are 32-bit little-endian integers, and the VDUID is the little-endian
representation of the UUID. The data unit is stored in the hash tree, alongside
the hash of the given page (see [integrity](./integrity.md#hash-tree)). The
data unit tends to follow large runs of consecutive values but sometimes jumps,
so its value cannot be calculated; rather, it must be read from the hash
tree.[^2]

[^2]:
    Due to the jumps, some data units are repeated, causing some pages to share
    a tweak. Identical plaintext pages then produce identical ciphertext, which
    is intended "to enable content updates to be distributed as ciphertext-only
    deltas and to support efficient block-level deduplication".

### Page Encryption

To encrypt or decrypt a page, the tweak, tweak key and data key are required. A
page is encrypted with XTS-AES as 256 consecutive 16-byte blocks.

First, the 16-byte tweak is encrypted with AES-128 using the tweak key to
produce the initial value `T`. For each subsequent block, `T` is treated as a
little-endian value and multiplied by `x` in the Galois Field GF(2¹²⁸) modulo
the irreducible polynomial `x¹²⁸ + x⁷ + x² + x + 1`, ensuring that each block
gets its own unique `T`.

Each 16-byte block is then transformed as `out = transform(in ⊕ T) ⊕ T`, where
`transform` is defined as:

- AES-128 encryption with the data key, to encrypt.
- AES-128 decryption with the data key, to decrypt.

The sequence of `T` tweak values is always derived with AES encryption of the
tweak, for both encryption and decryption. As the page size is a multiple of 16
bytes, ciphertext stealing is not needed.
