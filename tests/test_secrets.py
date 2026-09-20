from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.encodings import normalize
from haris.secrets import extract_tainted_values
from haris.trust import TrustView
from tests.factories import make_request


def _view_with(content: str, sensitivity: Sensitivity) -> TrustView:
    request = make_request(
        provenance={"prov-s": (TrustLevel.TRUSTED_INTERNAL, sensitivity)},
        conversation=[
            ConversationItem(role="tool", kind="tool_result", content=content, provenance_ids=["prov-s"])
        ],
    )
    return TrustView(request)


def test_extracts_reference_shaped_identifier():
    view = _view_with("Master services agreement reference CTR-SYN-906FAF7F88.", Sensitivity.CONFIDENTIAL)
    assert normalize("CTR-SYN-906FAF7F88") in extract_tainted_values(view)


def test_extracts_long_digit_run():
    view = _view_with("Account SYNTN123456789012345678 is active.", Sensitivity.CONFIDENTIAL)
    assert normalize("SYNTN123456789012345678") in extract_tainted_values(view)


def test_ignores_low_sensitivity_content():
    view = _view_with("Reference CTR-SYN-906FAF7F88.", Sensitivity.PUBLIC)
    assert extract_tainted_values(view) == set()


def test_ignores_ordinary_words():
    view = _view_with("The renewal requires Legal approval before November.", Sensitivity.CONFIDENTIAL)
    assert extract_tainted_values(view) == set()
