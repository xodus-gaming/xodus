## Integrity

MSIXVC packages are served from Microsoft's CDN over the insecure HTTP protocol
because they contain their own integrity information. This information can be
used to ensure that the package has not been tampered with and that it comes
from a trusted source. This is checked via the hash tree and the header's RSA
signature, respectively.

### Hash Tree

Following the `Mutable Data` section in the MSIXVC package is the `Hash Tree`
section. This section contains a Merkle hash tree which can be used to verify
the integrity of all the remaining pages of the package (the `User Data`,
`XVC Info` and `Drive Data` sections). Each page of the hash tree contains up
to 170 24-byte entries, which are truncated SHA-256 hashes.[^1] Because 4096 is
not a multiple of 24, the final 16 bytes of each page are filled with zeroes.
Each hash is calculated from a page of data (4096 bytes).[^2]

[^1]:
    Level 0 hash entries that point to encrypted data are also 24 bytes long,
    but the SHA-256 hash is truncated further to 20 bytes in order to make room
    for the 4-byte `data unit`. See
    [encryption](./encryption.md#region-encryption).

[^2]:
    For encrypted regions, the hash covers the ciphertext, so the package can
    be verified without the decryption key.

The hash tree is split into multiple levels. A hash tree level is a contiguous
sequence of pages of the hash tree that verify a contiguous region of pages:
the n-th entry of a level verifies the n-th page of the region. As the number
of entries in a level is not necessarily a multiple of 170, the last page of
each level may be padded with zeroes.

The levels in the hash tree act as layers: level 0 verifies the actual data,
and then each subsequent level verifies the level below it. Therefore, each
level is approximately 170 times smaller than the one below it. The topmost
level of the tree fits into a single page, and its hash is stored directly in
the header. Thus, a chain of trust is established: the hash stored in the
header verifies the topmost level of the tree, and each level verifies the one
below it. Since level 0 verifies the actual data, everything following the hash
tree is ultimately verified by a single hash in the header.

The levels are stored in order, starting with the topmost level and ending with
level 0. MSIXVC packages may have up to 4 hash tree levels, but they could have
fewer because levels stop being added once the topmost one fits into a single
page.

The size of the hash tree section is not stored in the header. Instead, its
size is calculated based on the number of pages it covers. Each page of the
hash tree covers 170 pages. Therefore, each level occupies exactly `⌈N / 170⌉`
pages, where `N` is the number of pages of either the actual data or the level
below it. The total number of pages occupied by the hash tree is the sum of
every level's size.[^3]

[^3]:
    This total can be approximated as `⌈D / (170 - 1)⌉` pages, where `D` is the
    number of data pages. This approximation is not exact because each level is
    rounded up to a whole page, whereas the approximation uses fractional
    pages.

For example, the hash trees for a 100 GiB game and a 15 GiB game occupy the
following number of pages:

|            | 100 GiB    | 15 GiB    |
| ---------- | ---------- | --------- |
| Data pages | 26,214,400 | 3,932,160 |
| Level 0    | 154,203    | 23,131    |
| Level 1    | 908        | 137       |
| Level 2    | 6          | 1         |
| Level 3    | 1          | -         |
| Total      | 155,118    | 23,269    |

### Header Signature

Every MSIXVC package begins with a 512-byte RSA signature that signs the
header. The header contains the hash of the topmost level of the tree, which
allows the entire hash tree to be authenticated. The hash tree can then be used
to verify the rest of the package. The only sections that aren't verified are
the `Embedded XVD` and the `Mutable Data` sections (those between the header
and the hash tree).

The signature is typically generated using Microsoft's private key. However,
unofficial packages might be signed with different keys. Trust in a package
depends on the trust placed in the corresponding public key.
