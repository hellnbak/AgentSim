"""Resolve static reviewed command references into argv arrays."""

from __future__ import annotations

import json
from importlib import resources
from typing import Mapping

from .integrity import verify_integrity


def load_command_catalog() -> dict[str, Mapping[str, object]]:
    resource = resources.files("agentsim.content.catalogs").joinpath("endpoint_commands.json")
    with resource.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)
    if value.get("schema_version") != "1.0" or value.get("kind") != "command-catalog":
        raise ValueError("built-in command catalog has an unsupported schema")
    verify_integrity(value, "commands")
    commands = value.get("commands")
    if not isinstance(commands, dict):
        raise ValueError("built-in command catalog is invalid")
    return commands


def resolve_command_sequence(command_ref: str, platform_name: str) -> tuple[tuple[str, ...], ...]:
    catalog = load_command_catalog()
    record = catalog.get(command_ref)
    if not isinstance(record, Mapping):
        raise ValueError(f"unknown command reference: {command_ref}")
    platforms = record.get("platforms")
    if not isinstance(platforms, Mapping):
        raise ValueError(f"command reference has no platform map: {command_ref}")
    raw_sequence = platforms.get(platform_name)
    if not isinstance(raw_sequence, list) or not raw_sequence:
        raise ValueError(f"command reference does not support platform: {platform_name}")
    sequence: list[tuple[str, ...]] = []
    for argv in raw_sequence:
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) or not argument for argument in argv)
        ):
            raise ValueError(f"command reference contains an invalid argv sequence: {command_ref}")
        sequence.append(tuple(argv))
    return tuple(sequence)
