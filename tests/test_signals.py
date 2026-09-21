import re

from haris.signals import REASON_CODES, Signal

CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


def test_every_reason_code_matches_the_contract_pattern():
    assert REASON_CODES, "vocabulary must not be empty"
    for code in REASON_CODES:
        assert CODE_PATTERN.fullmatch(code), code


def test_contribution_is_weight_times_value():
    signal = Signal(code="UNTRUSTED_INSTRUCTION_AUTHORITY", weight=0.4, value=0.5, detail="x")
    assert signal.contribution == 0.2


def test_no_reason_code_is_pure_vocabulary():
    """Every declared code must be emitted by some module.

    `TRUSTED_POLICY_CONFLICT` sat in this vocabulary with no implementation behind it.
    An auditor reading the code list saw a capability the defense did not have, which is
    a worse failure than the missing capability itself.
    """
    import pathlib

    from haris.signals import REASON_CODES

    source_dir = pathlib.Path(__file__).resolve().parents[1] / "src" / "haris"
    emitters = "\n".join(
        path.read_text(encoding="utf-8")
        for path in source_dir.glob("*.py")
        if path.name != "signals.py"
    )
    orphans = sorted(code for code in REASON_CODES if code not in emitters)
    assert not orphans, f"reason codes declared but never emitted: {orphans}"
