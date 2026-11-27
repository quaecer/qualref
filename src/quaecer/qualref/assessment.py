# SPDX-License-Identifier: Apache-2.0
"""Evaluate the qualification predicates against the accepted report view."""

from collections.abc import Iterable, Mapping
from fractions import Fraction
from hashlib import sha256
from typing import Any, Literal

from .temporal import evaluate_temporal
from .wire import BASE, View, basis, canonical, reason

Record = dict[str, Any]
Value = Literal["support", "opposition", "both", "neither"]
Execution = Literal["evaluated", "not_applicable", "not_run"]
VALUES: dict[tuple[bool, bool], Value] = {
    (True, False): "support",
    (False, True): "opposition",
    (True, True): "both",
    (False, False): "neither",
}
OUTCOMES = {
    "support": "passed",
    "opposition": "failed",
    "both": "cantTell",
    "neither": "cantTell",
}


def _comparison(record: Record) -> frozenset[bytes]:
    return frozenset(canonical(record[key]) for key in ("left", "right"))


def _pin_set(pins: Iterable[Record]) -> set[bytes]:
    return {canonical(pin) for pin in pins}


def _matches(rule: Record, report: Record) -> bool:
    operator = rule["operator"]
    if report["kind"] != operator:
        return False
    if operator in ("check", "control"):
        return bool(rule["criterion"] == report["criterion"])
    if operator == "dependence":
        return rule["dimension"] == report["dimension"] and _comparison(rule) == _comparison(report)
    if operator == "selection":
        return not _pin_set(rule["items"]).isdisjoint(_pin_set(report["required"]))
    selector = {"run_status": "run", "body": "artifact"}[operator]
    return bool(rule[selector] == report[selector])


def _single_observation(
    rule: Record, report: Record, supplied_body: tuple[int, str] | None
) -> Value:
    match rule["operator"]:
        case "check":
            if report["result"] == "pass":
                return "support"
            if report["result"] == "fail":
                return "opposition"
        case "control":
            if report["unit"] == rule["unit"] and report["observed"] is not None:
                distance = abs(Fraction(report["observed"]) - Fraction(rule["expected"]))
                return "support" if distance <= Fraction(rule["tolerance"]) else "opposition"
        case "run_status":
            if report["value"] == "succeeded":
                return "support"
            if report["value"] in ("failed", "interrupted"):
                return "opposition"
        case "body":
            if supplied_body is not None:
                recorded = (report["size"], report["raw_sha256"])
                return "support" if supplied_body == recorded else "opposition"
    return "neither"


def _selection(rule: Record, matching: Mapping[str, Record]) -> tuple[Value, set[str]]:
    selections = {
        report_id: (_pin_set(report["included"]), _pin_set(report["omitted"]))
        for report_id, report in matching.items()
    }
    contested_reports: set[str] = set()
    uncovered = False
    omitted = False
    for item in rule["items"]:
        pin = canonical(item)
        positive = {report_id for report_id, (included, _) in selections.items() if pin in included}
        negative = {report_id for report_id, (_, excluded) in selections.items() if pin in excluded}
        if positive and negative:
            contested_reports.update(positive | negative)
        elif negative:
            omitted = True
        elif not positive:
            uncovered = True
    if omitted:
        return "opposition", contested_reports
    if contested_reports:
        return "both", contested_reports
    return ("neither" if uncovered else "support"), contested_reports


def _dependence(rule: Record, matching: Mapping[str, Record]) -> tuple[Value, str, set[str]]:
    known = {
        report_id: report["relation"]
        for report_id, report in matching.items()
        if report["relation"] != "unknown"
    }
    relations = set(known.values())
    if len(relations) == 2:
        return "both", "unknown", set(known)
    if not relations:
        return "neither", "unknown", set()
    relation: str = next(iter(relations))
    value: Value = "support" if rule["required"] in ("known", relation) else "opposition"
    return value, relation, set()


def _ordered_reasons(records: Iterable[Record]) -> list[Record]:
    unique = {canonical(record): record for record in records}
    return [unique[key] for key in sorted(unique)]


def _finding(
    criterion: str,
    execution: Execution,
    value: Value,
    pins: list[dict[str, str]],
    reasons: list[Record],
) -> Record:
    outcome = {
        "not_applicable": "inapplicable",
        "not_run": "untested",
        "evaluated": OUTCOMES[value],
    }[execution]
    return {
        "criterion": criterion,
        "execution": execution,
        "value": value,
        "outcome": outcome,
        "basis": pins,
        "reasons": _ordered_reasons(reasons),
    }


def _scalar(view: View, rule: Record) -> tuple[Record, Record | None, list[Record]]:
    criterion: str = rule["id"]
    operator: str = rule["operator"]
    matching = {
        report_id: report for report_id, report in view.selected.items() if _matches(rule, report)
    }
    pins = basis(view, matching)
    dependence: Record | None = None
    inconsistencies: list[Record] = []
    reasons: list[Record] = []
    execution: Execution = "evaluated"
    if operator == "selection":
        value, contested = _selection(rule, matching)
    elif operator == "dependence":
        value, relation, contested = _dependence(rule, matching)
        dependence = {
            "dimension": rule["dimension"],
            "comparison": dict(
                zip(
                    ("left", "right"),
                    sorted((rule["left"], rule["right"]), key=lambda pin: pin["id"]),
                    strict=True,
                )
            ),
            "relation": relation,
            "reports": [view.pins[report_id] for report_id in sorted(matching)],
            "basis": pins,
        }
    else:
        supplied_body: tuple[int, str] | None = None
        if operator == "body":
            raw = view.bodies.get(canonical(rule["artifact"]))
            if raw is None:
                reasons.append(reason("missing_body", related=[rule["artifact"]["id"]]))
            else:
                supplied_body = (len(raw), "sha256:" + sha256(raw).hexdigest())
        observations = {
            report_id: _single_observation(rule, report, supplied_body)
            for report_id, report in matching.items()
        }
        positive = {report_id for report_id, claim in observations.items() if claim == "support"}
        negative = {report_id for report_id, claim in observations.items() if claim == "opposition"}
        value = VALUES[bool(positive), bool(negative)]
        contested = (positive | negative) if value == "both" else set()
        if (
            operator in ("check", "control")
            and matching
            and all(report["state"] == "not_run" for report in matching.values())
        ):
            execution = "not_run"

    if contested:
        conflict = reason(
            "conflicting_observations",
            criterion=criterion,
            reports=contested,
        )
        reasons.append(conflict)
        inconsistencies.append(conflict)
    if value == "neither":
        unaccepted = [
            report_id
            for report_id, report in view.reports.items()
            if report_id not in view.selected
            and report["subject"] == view.policy["subject"]
            and report["implementation"] == view.policy["implementation"]
            and _matches(rule, report)
        ]
        if unaccepted:
            reasons.append(reason("report_not_accepted", criterion=criterion, reports=unaccepted))
        if execution == "evaluated" and not reasons:
            reasons.append(reason("unavailable_report", criterion=criterion))

    return _finding(criterion, execution, value, pins, reasons), dependence, inconsistencies


def assess(view: View, clockcheck: str | None) -> Record:
    """Assemble direct findings and project their sceptical qualification."""
    policy = view.policy
    use = policy["use"]
    rules: list[Record] = policy["rules"]
    temporal = evaluate_temporal(view, clockcheck)
    findings: list[Record] = []
    dependence: dict[str, Record] = {}
    inconsistencies = list(temporal.inconsistencies)
    for rule in sorted(rules, key=lambda rule: rule["id"]):
        criterion = rule["id"]
        if use["kind"] not in rule["uses"]:
            findings.append(_finding(criterion, "not_applicable", "neither", [], []))
        elif rule["operator"] in ("coverage", "no_prelock_exposure"):
            findings.append(temporal.findings[criterion])
        else:
            finding, dependence_row, conflicts = _scalar(view, rule)
            findings.append(finding)
            inconsistencies.extend(conflicts)
            if dependence_row is not None:
                dependence.setdefault(dependence_row["dimension"], dependence_row)

    clock = temporal.clock_compatibility
    if inconsistencies or clock == "incompatible":
        consistency = "inconsistent"
    elif clock == "unresolved":
        consistency = "unresolved"
    else:
        consistency = "consistent"

    outcomes = {finding["outcome"] for finding in findings}
    if "failed" in outcomes:
        qualification = "prerequisites_failed"
    elif consistency == "consistent" and outcomes - {"inapplicable"} == {"passed"}:
        qualification = "prerequisites_satisfied"
    else:
        qualification = "prerequisites_unresolved"
    return {
        "profile": BASE + "result",
        "use": use["id"],
        "policy_digest": view.policy_digest,
        "use_registry_digest": policy["use_registry_digest"],
        "view_digest": view.view_digest,
        "subject": policy["subject"],
        "implementation": policy["implementation"],
        "clock_compatibility": clock,
        "consistency": consistency,
        "qualification": qualification,
        "authorization": "not_granted",
        "findings": findings,
        "coverage": temporal.coverage,
        "dependence": [dependence[dimension] for dimension in sorted(dependence)],
        "inconsistencies": _ordered_reasons(inconsistencies),
        "transfers": [],
        "resolving_sets": {"status": "not_run", "sets": [], "search_bound_reached": None},
    }
