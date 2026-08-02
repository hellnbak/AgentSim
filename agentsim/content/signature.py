"""Dependency-free verification of signed AgentSim content metadata."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from importlib import resources
from typing import Mapping


SIGNATURE_ALGORITHM = "rsa-pkcs1v15-sha256"
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _trust_store() -> Mapping[str, object]:
    resource = resources.files("agentsim.content").joinpath("trusted_keys.json")
    with resource.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)
    if not isinstance(value, Mapping):
        raise ValueError("AgentSim trust store is invalid")
    return value


def signature_payload(pack: Mapping[str, object], content_key: str) -> bytes:
    integrity = pack.get("integrity")
    if not isinstance(integrity, Mapping):
        raise ValueError("pack.integrity must be an object")
    identifier = pack.get("pack_id", pack.get("catalog_id"))
    value = {
        "schema_version": pack.get("schema_version"),
        "kind": pack.get("kind"),
        "content_id": identifier,
        "content_key": content_key,
        "digest": integrity.get("digest"),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def verify_signature(pack: Mapping[str, object], content_key: str) -> str | None:
    """Verify an optional trusted RSA signature and return its key ID."""

    integrity = pack.get("integrity")
    if not isinstance(integrity, Mapping):
        raise ValueError("pack.integrity must be an object")
    signature = integrity.get("signature")
    if signature is None:
        return None
    if not isinstance(signature, Mapping):
        raise ValueError("pack.integrity.signature must be an object")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ValueError(f"pack signature algorithm must be {SIGNATURE_ALGORITHM}")
    key_id = signature.get("key_id")
    encoded = signature.get("value")
    if not isinstance(key_id, str) or not isinstance(encoded, str):
        raise ValueError("pack signature requires key_id and base64 value")
    key = _trust_store().get(key_id)
    if not isinstance(key, Mapping):
        raise ValueError(f"pack signature key is not trusted: {key_id}")
    if key.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ValueError(f"trusted key does not support {SIGNATURE_ALGORITHM}")
    try:
        modulus = int(str(key["modulus_hex"]), 16)
        exponent = int(key.get("exponent", 65537))
        signature_bytes = base64.b64decode(encoded, validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("pack signature or trusted key is malformed") from exc
    width = (modulus.bit_length() + 7) // 8
    if len(signature_bytes) != width:
        raise ValueError("pack signature has an invalid length")
    recovered = pow(int.from_bytes(signature_bytes, "big"), exponent, modulus).to_bytes(
        width, "big"
    )
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(
        signature_payload(pack, content_key)
    ).digest()
    padding_length = width - len(digest_info) - 3
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    if padding_length < 8 or not hmac.compare_digest(recovered, expected):
        raise ValueError("pack signature verification failed")
    return key_id
