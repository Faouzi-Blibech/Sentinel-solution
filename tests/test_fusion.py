from haris.fusion import fuse
from haris.signals import CAPABILITY_DRIFT, GOAL_ALIGNED, SENSITIVE_TO_EXTERNAL_SINK, Signal


def test_no_active_signals_yields_low_risk():
    result = fuse([Signal(code=CAPABILITY_DRIFT, weight=0.4, value=0.0, detail="")])
    assert result.risk_score < 0.2
    assert result.active_codes == [GOAL_ALIGNED]


def test_risk_is_bounded_to_unit_interval():
    result = fuse(
        [
            Signal(code=SENSITIVE_TO_EXTERNAL_SINK, weight=0.6, value=1.0, detail=""),
            Signal(code=CAPABILITY_DRIFT, weight=0.4, value=1.0, detail=""),
        ]
    )
    assert 0.0 <= result.risk_score <= 1.0
    assert result.risk_score > 0.7


def test_active_codes_exclude_zero_signals():
    result = fuse(
        [
            Signal(code=SENSITIVE_TO_EXTERNAL_SINK, weight=0.6, value=1.0, detail=""),
            Signal(code=CAPABILITY_DRIFT, weight=0.4, value=0.0, detail=""),
        ]
    )
    assert result.active_codes == [SENSITIVE_TO_EXTERNAL_SINK]


def test_reason_codes_never_exceed_sixteen():
    signals = [Signal(code=f"SIGNAL_{i}", weight=0.1, value=1.0, detail="") for i in range(30)]
    assert len(fuse(signals).active_codes) <= 16


def test_confidence_is_higher_when_signals_agree():
    agree = fuse(
        [
            Signal(code=SENSITIVE_TO_EXTERNAL_SINK, weight=0.6, value=1.0, detail=""),
            Signal(code=CAPABILITY_DRIFT, weight=0.4, value=1.0, detail=""),
        ]
    )
    mixed = fuse(
        [
            Signal(code=SENSITIVE_TO_EXTERNAL_SINK, weight=0.6, value=0.5, detail=""),
            Signal(code=CAPABILITY_DRIFT, weight=0.4, value=0.5, detail=""),
        ]
    )
    assert agree.confidence > mixed.confidence
