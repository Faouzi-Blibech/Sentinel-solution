import pytest

from redteam.harness import ABLATION_ARMS, Arm, attacker_factory, by_family, render_families, render_table, summarize


class _Outcome:
    def __init__(self, scenario_id, attack_success=False, task_success=True):
        self.scenario_id = scenario_id
        self.attack_success = attack_success
        self.task_success = task_success


class _Metrics:
    btu, asr, cvr, fbr, uer, tui, dfi = 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0
    latency_p95_ms, defense_errors = 12.0, 0


class _Score:
    core, official_score, eligible, ood_factor = 0.99, 0.98, True, 1.0


class _Report:
    metrics, score = _Metrics(), _Score()
    scenario_count = 2
    outcomes = [_Outcome("a", attack_success=True), _Outcome("b")]


MAPPING = {"a": "indirect_prompt_injection", "b": "data_exfiltration"}


def test_arm_requires_exactly_one_defense_source():
    with pytest.raises(ValueError):
        Arm(label="bad")
    with pytest.raises(ValueError):
        Arm(label="bad", defense="keyword", defense_url="http://x")


def test_attacker_factory_resolves_our_adaptive_attacker():
    from redteam.attacker import AdaptiveAttacker

    assert attacker_factory("adaptive") is AdaptiveAttacker
    assert attacker_factory("none") is None


def test_attacker_factory_rejects_unknown_names():
    with pytest.raises(ValueError):
        attacker_factory("nope")


def test_by_family_counts_held_and_breached():
    table = by_family(_Report.outcomes, MAPPING)
    assert table["indirect_prompt_injection"] == {"scenarios": 1, "held": 0, "breached": 1, "invalid": 0, "untested": 0}
    assert table["data_exfiltration"] == {"scenarios": 1, "held": 1, "breached": 0, "invalid": 0, "untested": 0}


def test_summarize_records_breaches_by_name():
    row = summarize(Arm(label="haris", defense_url="http://x"), "public", _Report(), MAPPING)
    assert row["breached"] == ["a"]
    assert row["official"] == 0.98
    assert row["btu"] == 1.0


def test_render_table_handles_missing_metrics():
    """A defense that blocks everything reports None for some metrics; the table must survive."""
    rows = [{"label": "allow_all", "attacker": "none", "btu": None, "asr": None,
             "cvr": 0.0, "fbr": None, "official": 0.13, "eligible": False}]
    out = render_table(rows)
    assert "n/a" in out
    assert "NO" in out


def test_render_families_marks_missing_cells():
    rows = [summarize(Arm(label="haris", defense_url="http://x"), "public", _Report(), MAPPING)]
    out = render_families(rows)
    assert "indirect_prompt_injection" in out
    assert "0/1" in out


def test_taint_memory_ablation_arm_sits_right_after_no_data_flow():
    labels = [arm.label for arm in ABLATION_ARMS]
    i = labels.index("haris: no data flow")
    assert labels[i + 1] == "haris: no taint memory"
    taint_arm = ABLATION_ARMS[i + 1]
    assert taint_arm.ablate == ("taint",)
    assert taint_arm.in_process and taint_arm.attacker == "mutation"


def test_trust_and_authority_only_arm_still_means_every_other_stage_off():
    (arm,) = [a for a in ABLATION_ARMS if a.label == "haris: trust + authority only"]
    assert set(arm.ablate) == {"plan", "lifecycle", "dataflow", "rewrite", "memory", "taint"}
