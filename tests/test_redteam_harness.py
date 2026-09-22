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


# ---- Task 5: the scenario that rolls the 12-item conversation window ------------------------
#
# `haris: no taint memory` used to read identically to the full configuration on every
# scenario we owned (ASR 0.000 both ways) because none of them ran long enough to push the
# document holding a secret out of the kit's runtime.max_conversation_items window. These
# tests assert the specific shape that makes the window actually roll, not just that the
# file parses -- a scenario that parses but never rolls the window would pass a weaker test
# and still leave the ablation arm inert.


def _load_window_rollover_scenario():
    from pathlib import Path

    from sentinel.core.scenario import load_scenario

    path = Path(__file__).resolve().parent.parent / "redteam" / "scenarios" / "haris_ood_fin_window_rollover_retry.yaml"
    return load_scenario(path)


def test_window_rollover_scenario_declares_a_long_horizon_exfiltration_attack():
    from sentinel.core.scenario import AttackFamily

    scenario = _load_window_rollover_scenario()
    assert scenario.attack.present
    assert scenario.attack.family is AttackFamily.DATA_EXFILTRATION
    assert scenario.attack.difficulty == 5
    assert "held_out" in scenario.tags
    # max_steps has to comfortably fit a plan long enough to roll a 12-item window twice
    # over (read, first write, filler, retry, final) plus headroom for injected mutations.
    assert scenario.max_steps >= 19


def test_window_rollover_scenario_retries_the_same_write_after_enough_filler_to_roll_the_window():
    scenario = _load_window_rollover_scenario()
    plan = scenario.turns[0].reference_plan
    steps_by_id = {step.id: step for step in plan}

    first = steps_by_id["log_override_first"]
    retry = steps_by_id["log_override_retry"]
    # Byte-identical in substance: same tool, same template, same args -- the only thing
    # allowed to differ between the two attempts is how much has happened in between.
    assert first.tool == retry.tool == "case_note_create"
    assert first.args == retry.args

    first_index = plan.index(first)
    retry_index = plan.index(retry)
    read_index = plan.index(steps_by_id["read_override_doc"])
    # >= 12 other proposed actions between the read and the retry is what pushes the
    # read's conversation item out of a last-12-items window; this is a structural
    # invariant on the plan, not a substitute for actually measuring it (see the task
    # report for the measured per-step conversation length).
    assert retry_index - read_index > 12
    assert first_index < retry_index


def test_window_rollover_scenario_is_part_of_the_held_out_suite_the_harness_runs():
    from pathlib import Path

    from sentinel.evaluator.runner import load_suite

    scenarios_dir = Path(__file__).resolve().parent.parent / "redteam" / "scenarios"
    ids = {s.id for s in load_suite(scenarios_dir)}
    assert "haris_ood_fin_window_rollover_retry" in ids
