"""Explicit target profiles and target URI parsing."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class TargetProfile:
    """A normalized, explicitly named emulation target."""

    uri: str
    target_type: str
    identifier: str
    environment: str

    @classmethod
    def from_uri(cls, uri: str, *, environment: str | None = None) -> "TargetProfile":
        if not isinstance(uri, str) or not uri.strip():
            raise ValueError("target URI must be a non-empty string")
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        identifier = (parsed.netloc + parsed.path).strip("/")
        type_by_scheme = {
            "synthetic": "synthetic",
            "localhost": "localhost",
            "docker": "container",
            "lab-agent": "lab-agent",
            "ip": "ip-address",
            "cloud": "cloud-account",
        }
        target_type = type_by_scheme.get(scheme)
        if target_type is None:
            raise ValueError(
                "target URI scheme must be synthetic, localhost, docker, "
                "lab-agent, ip, or cloud"
            )
        if not identifier:
            raise ValueError("target URI must include an explicit identifier")
        if target_type == "ip-address":
            try:
                ipaddress.ip_address(identifier)
            except ValueError as exc:
                raise ValueError("ip target must contain a valid IP address") from exc
        elif target_type != "cloud-account" and not _NAME_PATTERN.fullmatch(identifier):
            raise ValueError("target identifier contains unsupported characters")
        if target_type == "cloud-account":
            parts = identifier.split("/")
            if len(parts) != 2 or not all(_NAME_PATTERN.fullmatch(part) for part in parts):
                raise ValueError("cloud target must be cloud://provider/account-name")
        inferred_environment = {
            "synthetic": "synthetic",
            "localhost": "lab",
            "container": "lab",
            "lab-agent": "lab",
            "ip-address": "lab",
            "cloud-account": "production",
        }[target_type]
        selected_environment = environment or inferred_environment
        if selected_environment not in {"synthetic", "lab", "staging", "production"}:
            raise ValueError("target environment is invalid")
        return cls(uri=uri, target_type=target_type, identifier=identifier, environment=selected_environment)
