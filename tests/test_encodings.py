import base64

from haris.encodings import normalize, variants


def test_normalize_strips_separators_and_case():
    assert normalize("C T R - s y n - 1 2 3") == normalize("CTRSYN123")


def test_variants_decode_base64():
    secret = "CTR-SYN-ABC123"
    encoded = base64.b64encode(secret.encode()).decode()
    found = dict(variants(f"ref {encoded}"))
    assert normalize(secret) in normalize(found["base64"])


def test_variants_decode_reversed():
    secret = "CTR-SYN-ABC123"
    found = dict(variants(secret[::-1]))
    assert normalize(secret) in normalize(found["reversed"])


def test_variants_always_include_plain():
    assert dict(variants("hello"))["plain"] == "hello"
