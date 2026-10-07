"""MurmurHash3 must stay byte-compatible with mmh3.hash (favicon DB depends on it)."""
from scanner._murmur import hash as mh


def test_known_vectors():
    assert mh("") == 0
    assert mh("foo") == -156908512
    assert mh("hello") == 613153351


def test_accepts_bytes_and_str_equivalently():
    assert mh("abc") == mh(b"abc")
