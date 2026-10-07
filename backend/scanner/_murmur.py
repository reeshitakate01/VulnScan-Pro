"""
Pure-Python MurmurHash3 (x86, 32-bit).

Drop-in replacement for ``mmh3.hash`` so VulnScan Pro has no compiled C
dependency (mmh3 ships no wheel for some Python/OS combos and otherwise needs
a C++ toolchain). Output is byte-for-byte identical to ``mmh3.hash(data,
seed=0, signed=True)``, which is what Shodan-style favicon fingerprinting and
the favicon hash database rely on.
"""


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """Return the signed 32-bit MurmurHash3 x86 hash of ``data``."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x3

    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | ((data[i + 3] & 0xFF) << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    rem = length & 0x3
    if rem == 3:
        k1 ^= (data[rounded_end + 2] & 0xFF) << 16
    if rem >= 2:
        k1 ^= (data[rounded_end + 1] & 0xFF) << 8
    if rem >= 1:
        k1 ^= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit to match mmh3.hash(..., signed=True)
    if h1 & 0x80000000:
        return -((h1 ^ 0xFFFFFFFF) + 1)
    return h1


def hash(data, seed: int = 0) -> int:  # noqa: A001 - mirror mmh3.hash signature
    """mmh3.hash-compatible helper accepting str or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return murmur3_32(data, seed)
