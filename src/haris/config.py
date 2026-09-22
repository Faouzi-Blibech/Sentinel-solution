"""Tunables in one place, so thresholds can be justified by measurement.

The stage switches exist for the ablation. The report has to show what each part of the
defense is actually buying, and the only honest way to do that is to run the defense
with that part removed -- comparing HARIS against somebody else's baseline measures two
different systems, not one system's components.
"""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Settings:
    block_threshold: float = 0.70
    escalate_threshold: float = 0.40
    max_metadata_bytes: int = 4096

    # Ablation switches. All on in the submitted configuration.
    authority_enabled: bool = True
    memory_enabled: bool = True
    plan_enabled: bool = True
    lifecycle_enabled: bool = True
    dataflow_enabled: bool = True
    rewrite_enabled: bool = True
    taint_enabled: bool = True

    def without(self, *stages: str) -> Settings:
        """The same configuration with named stages switched off."""
        unknown = [s for s in stages if not hasattr(self, f"{s}_enabled")]
        if unknown:
            raise ValueError(f"no such stage: {unknown}")
        return replace(self, **{f"{stage}_enabled": False for stage in stages})


SETTINGS = Settings()
