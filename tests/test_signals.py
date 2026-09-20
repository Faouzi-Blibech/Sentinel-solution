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
