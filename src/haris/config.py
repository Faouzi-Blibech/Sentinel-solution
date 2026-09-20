"""Tunables in one place, so thresholds can be justified by measurement."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    judge_enabled: bool = False
    block_threshold: float = 0.70
    escalate_threshold: float = 0.40
    max_metadata_bytes: int = 4096


SETTINGS = Settings()
