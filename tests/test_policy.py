from haris.policy import PolicyView

CONTEXT = {
    "policy_id": "enterprise_standard",
    "allowed_tools": ["email_read", "email_draft"],
    "consequential_tools": ["email_send"],
    "confirmation_required_tools": [],
    "internal_email_domains": ["atlas.example"],
}


def test_allowed_tools_are_parsed():
    assert PolicyView(CONTEXT).is_allowed("email_read")
    assert not PolicyView(CONTEXT).is_allowed("payment_execute")


def test_consequential_tools_are_parsed():
    assert PolicyView(CONTEXT).is_consequential("email_send")


def test_internal_destination_matches_domain():
    view = PolicyView(CONTEXT)
    assert view.is_internal_destination("legal@atlas.example")
    assert not view.is_internal_destination("partners@harbor-analytics.example")


def test_missing_policy_context_is_safe():
    """An empty policy must not crash and must not silently allow everything."""
    view = PolicyView({})
    assert view.allowed_tools == frozenset()
    assert not view.is_internal_destination("anyone@anywhere.example")
