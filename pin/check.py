"""Certificate pin parsing, matching, rotation, and batch verification."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Any, Mapping

_HASHERS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

_PIN_TYPES = {"cert", "spki"}
_WILDCARD_CHARS = ("*", "?")

DEFAULT_POLICY = {
    "max_backup_days": 7,
}

DEFAULT_ROTATION = timedelta(days=7)


def _coerce_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    raise TypeError("time values must be datetime objects or ISO-8601 strings")


def _normalise_type(value: Any) -> str:
    text = str(value if value is not None else "cert").strip().lower()
    if text in {"certificate", "cert", "crt"}:
        return "cert"
    if text in {"spki", "public_key", "public-key", "key"}:
        return "spki"
    return text


def _normalise_value(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().lower()
    return str(value if value is not None else "").strip().lower()


def _parse_entry(entry: Any) -> dict[str, Any]:
    if isinstance(entry, Mapping):
        return {
            "type": _normalise_type(entry.get("type", "cert")),
            "alg": str(entry.get("alg", "sha256")).strip().lower(),
            "value": _normalise_value(entry.get("value", "")),
            "backup": bool(entry.get("backup", False)),
            "valid_from": _coerce_datetime(entry.get("valid_from")),
            "valid_until": _coerce_datetime(entry.get("valid_until")),
        }

    if isinstance(entry, str):
        parts = entry.split(":", 3)
        if len(parts) < 3:
            raise ValueError("pin entries need type, algorithm, and value")
        backup = len(parts) == 4 and parts[3].strip().lower() in {
            "backup",
            "true",
            "1",
        }
        return {
            "type": _normalise_type(parts[0]),
            "alg": parts[1].strip().lower(),
            "value": _normalise_value(parts[2]),
            "backup": backup,
            "valid_from": None,
            "valid_until": None,
        }

    raise TypeError("pin entries must be mappings or colon-separated strings")


def parse_pins(entries: Any) -> list[dict[str, Any]]:
    """Parse pin entries into a normalised list.

    Each result contains type, alg, value, backup, valid_from, and valid_until.
    """
    if entries is None:
        return []
    if isinstance(entries, (str, Mapping)):
        entries = [entries]
    return [_parse_entry(entry) for entry in entries]


def _material_bytes(material: Any) -> bytes:
    if isinstance(material, str):
        return material.encode("utf-8")
    if isinstance(material, (bytes, bytearray, memoryview)):
        return bytes(material)
    raise TypeError("certificate material must be bytes or text")


def _pin_material(cert: Any, pin_type: str) -> Any:
    """Select the material a pin is computed over.

    ``cert`` pins bind the whole certificate, while ``spki`` pins bind only
    the subject public key info.
    """
    if isinstance(cert, Mapping):
        if pin_type == "spki":
            return cert.get("spki", b"")
        return cert.get("cert", b"")
    return cert


def fingerprint(cert: Any, alg: str) -> str:
    """Return the lowercase hexadecimal fingerprint for certificate material.

    The digest is computed with the declared algorithm; an unsupported
    algorithm raises instead of silently falling back.
    """
    algorithm = str(alg).strip().lower()
    hasher = _HASHERS.get(algorithm)
    if hasher is None:
        raise ValueError(f"unsupported fingerprint algorithm: {alg!r}")
    payload = _material_bytes(cert)
    return hasher(payload).hexdigest()


def match_pin(cert: Any, pin: Any) -> bool:
    """Return whether a certificate satisfies one pin.

    Pins must carry a non-empty, non-wildcard value and match the
    certificate's or public key's fingerprint exactly, using the algorithm
    declared on the pin. Anything else fails closed.
    """
    item = _parse_entry(pin)
    value = item["value"]

    # Empty or wildcard values must never match; they cannot identify a pin.
    if not value or any(char in value for char in _WILDCARD_CHARS):
        return False
    if item["type"] not in _PIN_TYPES:
        return False
    if item["alg"] not in _HASHERS:
        return False

    material = _pin_material(cert, item["type"])
    expected = fingerprint(material, item["alg"])
    # Constant-time comparison: pins are secrets and must not be probeable.
    return hmac.compare_digest(expected, value)


def _max_backup_days(policy: Mapping[str, Any] | None) -> float:
    effective = policy or DEFAULT_POLICY
    return float(effective.get("max_backup_days", DEFAULT_POLICY["max_backup_days"]))


def backup_allowed(
    pin: Any, now: datetime, policy: Mapping[str, Any] | None = None
) -> bool:
    """Return whether a backup pin may still participate in verification.

    A backup pin is only usable inside its declared rotation window
    (``valid_from <= now <= valid_until``). Once the window ends the old
    backup value is dead and must never match. Primary pins are not subject
    to rotation gating.
    """
    item = _parse_entry(pin)
    if not item["backup"]:
        return False

    start = item["valid_from"]
    end = item["valid_until"]
    if start is None or end is None or end < start:
        return False

    maximum = _max_backup_days(policy)
    if end - start > timedelta(days=maximum):
        return False

    return start <= now <= end


def check_set(
    pins: Any, policy: Mapping[str, Any] | None = None
) -> list[str]:
    """Return the problems found in a pin set."""
    problems: list[str] = []
    maximum = _max_backup_days(policy)

    for item in parse_pins(pins):
        if item["type"] not in _PIN_TYPES:
            problems.append("pin has an unsupported type")
        if item["alg"] not in _HASHERS:
            problems.append("pin declares an unsupported fingerprint algorithm")
        if not item["value"]:
            problems.append("pin value must not be empty")
        elif any(char in item["value"] for char in _WILDCARD_CHARS):
            problems.append("pin value must not contain wildcard characters")

        if item["backup"]:
            start = item["valid_from"]
            end = item["valid_until"]
            if start is None or end is None:
                problems.append("backup pin is missing its rotation window")
            elif end <= start:
                problems.append("backup pin rotation window is invalid")
            elif end - start > timedelta(days=maximum):
                problems.append("backup pin rotation window exceeds policy")

    return problems


def verify(
    cert: Any,
    pins: Any,
    now: datetime,
    policy: Mapping[str, Any] | None = None,
) -> bool:
    """Verify one certificate against a pin set at a point in time.

    Fails closed: an empty/invalid pin set rejects every certificate, and
    only an exact match against an in-force pin accepts one.
    """
    items = parse_pins(pins)
    if not items:
        return False

    effective = policy or DEFAULT_POLICY
    if check_set(items, effective):
        return False

    for item in items:
        if item["backup"] and not backup_allowed(item, now, effective):
            continue
        if match_pin(cert, item):
            return True

    return False


def rotate(pins: Any, new_pin: Any, now: datetime) -> list[dict[str, Any]]:
    """Add a new pin and return the rotated set."""
    current = parse_pins(pins)
    incoming = _parse_entry(new_pin)
    return current + [incoming]


def _connection_parts(connection: Any, index: int) -> tuple[Any, Any]:
    if isinstance(connection, Mapping):
        if "cert" in connection or "spki" in connection:
            name = connection.get("id", connection.get("name", index))
            return name, connection
    if isinstance(connection, (tuple, list)) and len(connection) == 2:
        return connection[0], connection[1]
    return index, connection


def pin_batch(
    connections: Any,
    pins: Any,
    now: datetime,
    policy: Mapping[str, Any] | None = None,
) -> dict[Any, bool]:
    """Verify several independent connections against the same pin set.

    Each connection is verified on its own; one result is never shared with
    or reused for another connection.
    """
    effective = policy or DEFAULT_POLICY
    results: dict[Any, bool] = {}

    for index, connection in enumerate(connections):
        name, cert = _connection_parts(connection, index)
        results[name] = verify(cert, pins, now, effective)

    return results
