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


def fingerprint(cert: Any, alg: str) -> str:
    """Return the lowercase hexadecimal fingerprint for certificate material."""
    hasher = _HASHERS.get(str(alg).strip().lower())
    if hasher is None:
        raise ValueError(f"unsupported fingerprint algorithm: {alg!r}")
    if isinstance(cert, Mapping):
        material = cert.get("cert", b"")
    else:
        material = cert
    payload = _material_bytes(material)
    return hasher(payload).hexdigest()


def match_pin(cert: Any, pin: Any) -> bool:
    """Return whether a certificate satisfies one pin."""
    item = _parse_entry(pin)
    value = item["value"]

    if not value:
        return False
    if "*" in value or "?" in value:
        return False
    if item["alg"] not in _HASHERS:
        return False

    if isinstance(cert, Mapping):
        if item["type"] == "spki":
            material = cert.get("spki", b"")
        else:
            material = cert.get("cert", b"")
    else:
        material = cert

    expected = fingerprint(material, item["alg"])
    return hmac.compare_digest(expected, value)


def _max_backup_days(policy: Mapping[str, Any] | None) -> float:
    effective = policy or DEFAULT_POLICY
    return float(effective.get("max_backup_days", DEFAULT_POLICY["max_backup_days"]))


def backup_allowed(
    pin: Any, now: datetime, policy: Mapping[str, Any] | None = None
) -> bool:
    """Return whether a backup pin may still participate in verification."""
    item = _parse_entry(pin)
    if not item["backup"]:
        return False

    start = item["valid_from"]
    end = item["valid_until"]
    if start is None or end is None:
        return False
    if end <= start:
        return False
    if end - start > timedelta(days=_max_backup_days(policy)):
        return False
    return start <= now <= end


def check_set(
    pins: Any, policy: Mapping[str, Any] | None = None
) -> list[str]:
    """Return the problems found in a pin set."""
    problems: list[str] = []
    maximum = _max_backup_days(policy)

    for item in parse_pins(pins):
        if not item["value"]:
            problems.append("pin value must not be empty")
        elif "*" in item["value"] or "?" in item["value"]:
            problems.append("pin value must not contain wildcards")
        if item["alg"] not in _HASHERS:
            problems.append("pin algorithm is not supported")
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
    """Verify one certificate against a pin set at a point in time."""
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


def rotate(
    pins: Any,
    new_pin: Any,
    now: datetime,
    rotation: timedelta | None = None,
) -> list[dict[str, Any]]:
    """Add a new pin and return the rotated set.

    Existing primary pins are demoted to backup pins whose rotation window
    starts at ``now`` and ends after ``rotation`` (default 7 days); once the
    window closes the old pins no longer verify.
    """
    window = rotation if rotation is not None else DEFAULT_ROTATION
    rotated: list[dict[str, Any]] = []
    for item in parse_pins(pins):
        if item["backup"]:
            rotated.append(item)
        else:
            rotated.append(
                {
                    **item,
                    "backup": True,
                    "valid_from": now,
                    "valid_until": now + window,
                }
            )
    incoming = {**_parse_entry(new_pin), "backup": False}
    rotated.append(incoming)
    return rotated


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
    """Verify several independent connections against the same pin set."""
    effective = policy or DEFAULT_POLICY
    results: dict[Any, bool] = {}

    for index, connection in enumerate(connections):
        name, cert = _connection_parts(connection, index)
        results[name] = verify(cert, pins, now, effective)

    return results