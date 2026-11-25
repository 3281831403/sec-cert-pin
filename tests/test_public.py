import hashlib
from datetime import datetime, timezone

from pin.check import fingerprint, pin_batch, verify

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
POLICY = {
    "max_backup_days": 7,
}

CERT = {
    "cert": b"public-leaf-certificate-der",
    "spki": b"public-leaf-subject-public-key-info",
}
OTHER_CERT = {
    "cert": b"public-other-certificate-der",
    "spki": b"public-other-subject-public-key-info",
}


def _pin(material, kind, alg="sha256", **extra):
    entry = {
        "type": kind,
        "alg": alg,
        "value": hashlib.new(alg, material).hexdigest(),
        "backup": False,
        "valid_from": None,
        "valid_until": None,
    }
    entry.update(extra)
    return entry


def test_fingerprint_uses_declared_algorithm():
    expected = hashlib.sha512(CERT["cert"]).hexdigest()
    assert fingerprint(CERT["cert"], "sha512") == expected


def test_exact_spki_pin_is_accepted():
    pin = _pin(CERT["spki"], "spki")
    assert verify(CERT, [pin], NOW, POLICY) is True


def test_nonmatching_pin_is_rejected():
    full = hashlib.sha256(CERT["cert"]).hexdigest()
    pin = _pin(CERT["cert"], "cert", value=full[:-2])
    assert verify(CERT, [pin], NOW, POLICY) is False


def test_empty_pin_is_rejected():
    pin = _pin(CERT["cert"], "cert", value="")
    assert verify(CERT, [pin], NOW, POLICY) is False


def test_batch_connections_are_independent():
    pin = _pin(CERT["cert"], "cert")
    results = pin_batch(
        [("allowed", CERT), ("denied", OTHER_CERT)],
        [pin],
        NOW,
    )
    assert results == {"allowed": True, "denied": False}