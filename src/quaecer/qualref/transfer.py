# SPDX-License-Identifier: Apache-2.0
"""Carry matching findings across the declared use order."""

from __future__ import annotations

from collections.abc import Callable
from fractions import Fraction
from typing import Any

from .wire import BASE, View, canonical, digest, instant


def _reachable(view: View, target: str, source: str) -> bool:
    successors: dict[str, set[str]] = {}
    for edge in view.registry["edges"]:
        successors.setdefault(edge["target"], set()).add(edge["source"])
    pending = [target]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == source:
            return True
        visited.add(current)
        pending.extend(successors.get(current, set()) - visited)
    return False


def _instance(policy: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    predicate = {key: value for key, value in rule.items() if key not in {"id", "uses"}}
    settings = {"conflict_policy": policy["conflict_policy"]}
    operator = rule["operator"]
    if operator == "control":
        predicate["expected"] = str(Fraction(rule["expected"]))
        predicate["tolerance"] = str(Fraction(rule["tolerance"]))
    elif operator == "selection":
        predicate["items"] = sorted(rule["items"], key=canonical)
    elif operator == "dependence":
        predicate["left"], predicate["right"] = sorted((rule["left"], rule["right"]), key=canonical)
    elif operator == "coverage":
        settings["window"] = {
            key: instant(value).isoformat() for key, value in policy["window"].items()
        }
    elif operator == "no_prelock_exposure":
        settings.update(
            start=instant(policy["history_scope"]["start"]).isoformat(),
            lock_at=instant(policy["lock_at"]).isoformat(),
            channels=sorted(policy["channels"]),
            forbidden=sorted(policy["forbidden"], key=canonical),
        )
    if operator in {"coverage", "no_prelock_exposure"}:
        settings.update(
            scope_margin_us=policy["scope_margin_us"], defeat_scope=policy["defeat_scope"]
        )
    return {
        "profile": BASE + "criterion-instance",
        "predicate": predicate,
        "settings": settings,
    }


def _eligible(result: dict[str, Any]) -> bool:
    return bool(
        result["clock_compatibility"] == "compatible" and result["consistency"] == "consistent"
    )


def _definite(finding: dict[str, Any]) -> bool:
    return finding["execution"] == "evaluated" and finding["outcome"] in {"passed", "failed"}


def _applicable(view: View) -> dict[str, dict[str, Any]]:
    kind = view.policy["use"]["kind"]
    return {rule["id"]: rule for rule in view.policy["rules"] if kind in rule["uses"]}


def _retag(finding: dict[str, Any], target_id: str) -> dict[str, Any]:
    source_id = finding["criterion"]
    reasons = [
        {**reason, "criterion": target_id} if reason["criterion"] == source_id else reason
        for reason in finding["reasons"]
    ]
    return {**finding, "criterion": target_id, "reasons": sorted(reasons, key=canonical)}


def _qualification(result: dict[str, Any]) -> str:
    outcomes = {finding["outcome"] for finding in result["findings"]}
    if "failed" in outcomes:
        return "prerequisites_failed"
    if _eligible(result) and "passed" in outcomes and outcomes <= {"passed", "inapplicable"}:
        return "prerequisites_satisfied"
    return "prerequisites_unresolved"


def carry(source: View, target: View, assess: Callable[[View], dict[str, Any]]) -> dict[str, Any]:
    """Assess both views and carry only exact, definite, applicable matches."""
    source_use = source.policy["use"]
    target_use = target.policy["use"]
    if source.view_digest != target.view_digest:
        raise ValueError("transfer requires one exact accepted view")
    if source_use["id"] == target_use["id"] and source_use != target_use:
        raise ValueError("transfer changes a declared use")
    if not _reachable(target, target_use["kind"], source_use["kind"]):
        raise ValueError("registry does not permit this direction of transfer")

    source_result = assess(source)
    target_result = assess(target)
    if not (_eligible(source_result) and _eligible(target_result)):
        return target_result

    source_rules = _applicable(source)
    sources: dict[bytes, dict[str, Any]] = {}
    for finding in sorted(source_result["findings"], key=lambda finding: finding["criterion"]):
        source_id = finding["criterion"]
        if source_id in source_rules and _definite(finding):
            instance = _instance(source.policy, source_rules[source_id])
            sources.setdefault(canonical(instance), finding)

    target_rules = _applicable(target)
    carried: list[dict[str, Any]] = []
    certificates: list[dict[str, str]] = []
    for direct in sorted(target_result["findings"], key=lambda finding: finding["criterion"]):
        target_id = direct["criterion"]
        if target_id not in target_rules or not _definite(direct):
            carried.append(direct)
            continue
        instance = _instance(target.policy, target_rules[target_id])
        finding = sources.get(canonical(instance))
        if (
            finding is None
            or finding["value"] != direct["value"]
            or finding["outcome"] != direct["outcome"]
        ):
            carried.append(direct)
            continue

        carried.append(_retag(finding, target_id))
        certificates.append(
            {
                "source_use": source_use["id"],
                "target_use": target_use["id"],
                "source_policy_digest": source.policy_digest,
                "target_policy_digest": target.policy_digest,
                "view_digest": target.view_digest,
                "use_registry_digest": digest(target.registry),
                "criterion_digest": digest(instance),
                "source_criterion": finding["criterion"],
                "target_criterion": target_id,
                "source_finding_digest": digest(finding),
            }
        )
    result = {**target_result, "findings": carried, "transfers": certificates}
    result["qualification"] = _qualification(result)
    return result
