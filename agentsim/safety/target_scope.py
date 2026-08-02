"""Target allowlist matching without implicit production scope."""

from __future__ import annotations

import ipaddress

from agentsim.models.target import TargetProfile


def target_is_allowed(target: TargetProfile, allowed_targets: tuple[str, ...]) -> bool:
    """Match exact named targets or explicit CIDR entries."""

    for allowed in allowed_targets:
        if allowed == target.uri:
            return True
        if allowed.startswith("cidr://") and target.target_type == "ip-address":
            try:
                network = ipaddress.ip_network(allowed.removeprefix("cidr://"), strict=True)
                address = ipaddress.ip_address(target.identifier)
            except ValueError:
                continue
            if address in network:
                return True
    return False
