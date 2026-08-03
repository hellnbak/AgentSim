"""Maintainer helper for digesting and RSA-signing reviewed AgentSim content."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentsim.content.integrity import content_digest
from agentsim.content.signature import SIGNATURE_ALGORITHM, signature_payload


def sign_content(
    path: str | Path, *, content_key: str, private_key: str | Path, key_id: str
) -> None:
    selected = Path(path)
    value = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or content_key not in value:
        raise ValueError(f"{selected} does not contain {content_key}")
    integrity = value.setdefault("integrity", {})
    if not isinstance(integrity, dict):
        raise ValueError("integrity must be an object")
    integrity["algorithm"] = "sha256"
    integrity["digest"] = content_digest(value[content_key])
    integrity.pop("signature", None)
    completed = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(Path(private_key))],
        input=signature_payload(value, content_key),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace").strip())
    integrity["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "value": base64.b64encode(completed.stdout).decode("ascii"),
    }
    selected.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Update a reviewed content digest and sign it with an external RSA private key."
    )
    parser.add_argument("path")
    parser.add_argument(
        "content_key", choices=("abilities", "campaigns", "commands", "rules")
    )
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args(argv)
    sign_content(
        args.path,
        content_key=args.content_key,
        private_key=args.private_key,
        key_id=args.key_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
