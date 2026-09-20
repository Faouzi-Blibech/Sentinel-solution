from sentinel.core.provenance import Sensitivity, TrustLevel

from haris.trust import TrustView
from tests.factories import make_request


def test_unknown_provenance_defaults_to_least_trusted():
    view = TrustView(make_request())
    assert view.trust_of(["prov-does-not-exist"]) is TrustLevel.ADVERSARY_CONTROLLED


def test_trust_is_the_least_trusted_of_several():
    request = make_request(
        provenance={
            "prov-a": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.INTERNAL),
            "prov-b": (TrustLevel.UNTRUSTED_EXTERNAL, Sensitivity.INTERNAL),
        }
    )
    assert TrustView(request).trust_of(["prov-a", "prov-b"]) is TrustLevel.UNTRUSTED_EXTERNAL


def test_sensitivity_is_the_most_sensitive_of_several():
    request = make_request(
        provenance={
            "prov-a": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.PUBLIC),
            "prov-b": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL),
        }
    )
    assert TrustView(request).sensitivity_of(["prov-a", "prov-b"]) is Sensitivity.CONFIDENTIAL


def test_empty_provenance_is_not_authoritative():
    """No provenance means we cannot prove trust, so it must not grant authority."""
    view = TrustView(make_request())
    assert not view.trust_of([]).is_trusted
