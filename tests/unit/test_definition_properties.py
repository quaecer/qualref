# SPDX-License-Identifier: Apache-2.0
"""Exercise the transfer, removal and scope definitions on finite domains."""

import shutil
import unittest
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import combinations, product
from typing import Any

from quaecer.qualref.assessment import assess
from quaecer.qualref.transfer import carry
from quaecer.qualref.wire import BASE, bind, digest

_USES = ["computational_reanalysis", "new_empirical_anchor", "held_out", "prospective_locked"]
_ORDER = {(kind, kind) for kind in _USES} | {
    (_USES[0], _USES[1]),
    (_USES[0], _USES[2]),
    (_USES[0], _USES[3]),
    (_USES[3], _USES[2]),
}
_REGISTRY = {
    "format": "qualification-use-registry@1",
    "uses": _USES,
    "edges": [{"target": a, "source": b} for a, b in sorted(_ORDER) if a != b],
    "closure": "reflexive_transitive",
    "instance_relation": "canonical_semantic_equality",
}
_ZERO = datetime(2026, 1, 1, tzinfo=UTC)


def _pin(name: str) -> dict[str, str]:
    identifier = "urn:example:definition:" + name
    return {"id": identifier, "digest": digest(identifier)}


_SUBJECT = _pin("subject")
_IMPL = _pin("implementation")
_CLAIM = _pin("claim")
_ISSUER = _pin("issuer")
_RESOURCE = _pin("resource")
_SCHEME = BASE + "occurrence/explicit-id"


def _time(value: int) -> str:
    return (_ZERO + timedelta(microseconds=value)).isoformat().replace("+00:00", "Z")


def _interval(start: int, end: int) -> dict[str, str]:
    return {"start": _time(start), "end": _time(end)}


def _report(name: str, kind: str, **fields: Any) -> dict[str, Any]:
    return {
        "id": _pin(name)["id"],
        "kind": kind,
        "subject": _SUBJECT,
        "implementation": _IMPL,
        "issuer": _ISSUER,
        "basis": [_ISSUER],
        **fields,
    }


def _capture(
    name: str,
    start: int,
    end: int,
    *,
    accuracy: int = 0,
    clock: str = "clock",
    status: str = "complete",
    observer: str = _ISSUER["id"],
    channel: str = "context",
    entries: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    inventory = list(entries)
    return _report(
        name,
        "completeness",
        observer=observer,
        channels=[channel],
        interval=_interval(start, end),
        scope_kind="capture_window",
        status=status,
        selection_rule="all_information_uses",
        clock_id=_pin(clock)["id"],
        accuracy_us=accuracy,
        identity_scheme=_SCHEME,
        entries=inventory,
        inventory_digest=digest(inventory),
        segments=[],
    )


def _exposure(name: str, at: int, *, before: int = 0, channel: str = "context") -> dict[str, Any]:
    return _report(
        name,
        "exposure",
        channel=channel,
        resource=_RESOURCE,
        event_class="information_use",
        clock_id=_pin("report-clock")["id"],
        identity_scheme=_SCHEME,
        occurrence_id=_pin(name + "-occurrence")["id"],
        same_as=[],
        at=_time(at),
        uncertainty_before_us=before,
        uncertainty_after_us=0,
    )


def _typed(report: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "channel",
        "resource",
        "event_class",
        "occurrence_id",
        "same_as",
        "at",
        "uncertainty_before_us",
        "uncertainty_after_us",
    )
    return {
        **{key: report[key] for key in keys},
        "kind": "typed",
        "event_id": report["id"],
        "usage_digest": digest(report),
    }


def _clock_maps(
    readings: dict[str, set[int]], accuracy: int
) -> Iterator[dict[tuple[str, int], int]]:
    """Enumerate monotone endpoint readings in a finite half-microsecond domain."""
    keys = [
        (clock, reading) for clock, values in sorted(readings.items()) for reading in sorted(values)
    ]
    choices = [range(2 * (reading - accuracy), 2 * (reading + accuracy) + 1) for _, reading in keys]
    for values in product(*choices):
        if all(
            left[0] != right[0] or a <= b
            for left, right, a, b in zip(keys, keys[1:], values, values[1:], strict=False)
        ):
            yield dict(zip(keys, values, strict=True))


def _request(
    kind: str,
    operator: str,
    label: str,
    reports: list[dict[str, Any]],
    accepted: tuple[dict[str, Any], ...],
    *,
    margin: int = 0,
) -> dict[str, Any]:
    rule = {"id": label, "uses": [kind], "operator": operator}
    if operator == "coverage":
        rule["channel"] = "context"
    elif operator == "check":
        rule["criterion"] = "quality"
    use = _pin(kind)["id"]
    policy = {
        "profile": BASE + "policy",
        "use": {
            "id": use,
            "kind": kind,
            "question": "Does the predicate hold?",
            "claim": _CLAIM,
            "scope": "Definition check",
        },
        "subject": _SUBJECT,
        "implementation": _IMPL,
        "use_registry_digest": digest(_REGISTRY),
        "window": _interval(0, 4),
        "history_scope": {"start": _time(0)},
        "lock_at": _time(4),
        "channels": ["context"],
        "forbidden": [_RESOURCE] if operator == "no_prelock_exposure" else [],
        "rules": [rule],
        "conflict_policy": "sceptical",
        "scope_margin_us": margin,
        "defeat_scope": "segment",
    }
    common = {
        "policy_digest": digest(policy),
        "use": use,
        "subject": _SUBJECT,
        "implementation": _IMPL,
    }
    return {
        "profile": BASE + "request",
        "operation": "assess",
        "policy": policy,
        "use_registry": _REGISTRY,
        "evidence": {
            **common,
            "profile": BASE + "evidence",
            "claim": _CLAIM,
            "reports": reports,
            "references": [_SUBJECT, _IMPL, _CLAIM, _ISSUER, _RESOURCE],
        },
        "caller": {
            **common,
            "use_registry_digest": digest(_REGISTRY),
            "bodies": [],
            "report_pins": [{"id": r["id"], "digest": digest(r)} for r in accepted],
        },
    }


class TestDefinitionProperties(unittest.TestCase):
    """Exhaust every combination in directly constructed small domains."""

    def test_transfer_commutes_with_direct_assessment(self) -> None:
        """P1 preserves one exact predicate on every ordered pair of built-in uses."""
        observations = [
            _report("support", "check", criterion="quality", state="ran", result="pass"),
            _report("opposition", "check", criterion="quality", state="ran", result="fail"),
        ]
        selections = [picked for size in range(3) for picked in combinations(observations, size)]
        for source, target, chosen in product(_USES, _USES, selections):
            with self.subTest(source=source, target=target, count=len(chosen)):
                left = bind(_request(source, "check", "source", observations, chosen))
                right = bind(_request(target, "check", "target", observations, chosen))
                if (target, source) not in _ORDER:
                    with self.assertRaises(ValueError):
                        carry(left, right, lambda view: assess(view, None))
                    continue
                result = carry(left, right, lambda view: assess(view, None))
                direct = assess(right, None)
                self.assertEqual(result["findings"], direct["findings"])
                self.assertEqual(result["qualification"], direct["qualification"])
                self.assertEqual(result["authorization"], "not_granted")
                self.assertEqual(len(result["transfers"]), int(len(chosen) == 1))

    def test_consistent_scalar_removal_cannot_add_knowledge(self) -> None:
        """P2 keeps or weakens consistent findings after accepted report deletion."""
        observations = [
            _report("pass-a", "check", criterion="quality", state="ran", result="pass"),
            _report("pass-b", "check", criterion="quality", state="ran", result="pass"),
            _report("fail", "check", criterion="quality", state="ran", result="fail"),
        ]
        for size in range(1, 4):
            for selected in combinations(observations, size):
                result = assess(
                    bind(_request(_USES[0], "check", "check", observations, selected)), None
                )
                if result["consistency"] != "consistent":
                    continue
                before = result["findings"][0]["value"]
                for remaining in combinations(selected, size - 1):
                    after = assess(
                        bind(_request(_USES[0], "check", "check", observations, remaining)), None
                    )
                    self.assertIn(after["findings"][0]["value"], {before, "neither"})

    def test_single_clock_coverage_respects_every_endpoint_map(self) -> None:
        """P3 checks coverage against every bounded map of a single interval."""
        solver = shutil.which("clockcheck")
        self.assertIsNotNone(solver, "install the Clockcheck test dependency")
        for accuracy, start, end in product((0, 1), (-2, -1, 0, 1), (3, 4, 5, 6)):
            capture = _capture("capture", start, end, accuracy=accuracy)
            view = bind(
                _request(_USES[3], "coverage", "history", [capture], (capture,), margin=accuracy)
            )
            finding = assess(view, solver)["findings"][0]["outcome"]
            covered_in_every_map = all(
                a <= 0 and b >= 4
                for a, b in product(
                    range(start - accuracy, start + accuracy + 1),
                    range(end - accuracy, end + accuracy + 1),
                )
                if a <= b
            )
            with self.subTest(accuracy=accuracy, start=start, end=end):
                self.assertEqual(finding == "passed", covered_in_every_map)

    def test_removal_can_restore_a_finding_from_a_conflict(self) -> None:
        """P2's consistent-start premise excludes resolution of a witnessed conflict."""
        support = _report("support", "check", criterion="quality", state="ran", result="pass")
        opposition = _report("opposition", "check", criterion="quality", state="ran", result="fail")
        reports = [support, opposition]
        before = assess(bind(_request(_USES[0], "check", "check", reports, tuple(reports))), None)
        after = assess(bind(_request(_USES[0], "check", "check", reports, (support,))), None)
        self.assertEqual(before["consistency"], "inconsistent")
        self.assertEqual(before["findings"][0]["value"], "both")
        self.assertEqual(after["consistency"], "consistent")
        self.assertEqual(after["qualification"], "prerequisites_satisfied")

    def test_consistent_temporal_removal_cannot_add_knowledge(self) -> None:
        """P2 checks finding, gate and consistency on every smaller selected subset."""
        solver = shutil.which("clockcheck")
        self.assertIsNotNone(solver, "install the Clockcheck test dependency")
        earlier = _exposure("earlier", 2)
        later = _exposure("later", 5)
        other_observer = _capture(
            "partial", 0, 4, status="incomplete", observer=_pin("other")["id"]
        )
        pools = (
            [_capture("cover", -1, 5), other_observer, later],
            [_capture("typed", -1, 5, entries=(_typed(earlier),)), earlier, other_observer],
            [
                _capture(
                    "reference", -1, 5, entries=({"kind": "reference", "event_id": later["id"]},)
                ),
                later,
                other_observer,
            ],
        )
        observed = set()
        for index, reports in enumerate(pools):
            for operator in ("coverage", "no_prelock_exposure"):
                results = {}
                for size in range(len(reports) + 1):
                    for chosen in combinations(range(len(reports)), size):
                        accepted = tuple(reports[n] for n in chosen)
                        results[chosen] = assess(
                            bind(_request(_USES[3], operator, "history", reports, accepted)), solver
                        )
                        deleted = assess(
                            bind(_request(_USES[3], operator, "history", list(accepted), accepted)),
                            solver,
                        )
                        self.assertEqual(deleted, results[chosen])
                for chosen, before in results.items():
                    if before["consistency"] != "consistent":
                        continue
                    value = before["findings"][0]["value"]
                    observed.add(value)
                    for remaining, after in results.items():
                        if not set(remaining) < set(chosen):
                            continue
                        with self.subTest(
                            pool=index, operator=operator, before=chosen, after=remaining
                        ):
                            self.assertIn(after["findings"][0]["value"], {value, "neither"})
                            self.assertIn(
                                after["qualification"],
                                {before["qualification"], "prerequisites_unresolved"},
                            )
                            self.assertIn(after["consistency"], {"consistent", "unresolved"})
        self.assertEqual(observed, {"support", "opposition", "neither"})

    def test_composed_coverage_in_every_sampled_clock_world(self) -> None:
        """P3 checks composed scope and shared versus independent boundaries."""
        solver = shutil.which("clockcheck")
        self.assertIsNotNone(solver, "install the Clockcheck test dependency")
        for shared, left_end, right_start in product((False, True), (1, 2), (1, 2, 3)):
            right_clock = "left" if shared else "right"
            spans = [("left", -1, left_end), (right_clock, right_start, 5)]
            captures = [
                _capture(f"unit-{n}", a, b, accuracy=1, clock=clock)
                for n, (clock, a, b) in enumerate(spans)
            ]
            readings: dict[str, set[int]] = {}
            for clock, a, b in spans:
                readings.setdefault(clock, set()).update((a, b))
            view = bind(
                _request(_USES[3], "coverage", "history", captures, tuple(captures), margin=1)
            )
            result = assess(view, solver)
            with self.subTest(shared=shared, left_end=left_end, right_start=right_start):
                self.assertEqual(result["consistency"], "consistent")
                self.assertEqual(
                    result["findings"][0]["outcome"] == "passed",
                    right_start + (0 if shared else 2) <= left_end,
                )
                regions = result["coverage"][0]["window"]["covered"]
                for times in _clock_maps(readings, 1):
                    for tick in range(8):
                        # Reported regions have integral microsecond boundaries.
                        point = _time(tick // 2)
                        if any(
                            r["interval"]["start"] <= point < r["interval"]["end"] for r in regions
                        ):
                            self.assertTrue(
                                any(
                                    times[clock, a] <= tick < times[clock, b]
                                    for clock, a, b in spans
                                )
                            )

    def test_absence_pass_excludes_known_and_fresh_forbidden_events(self) -> None:
        """P3 compares absence passes to a finite event and endpoint world model."""
        solver = shutil.which("clockcheck")
        self.assertIsNotNone(solver, "install the Clockcheck test dependency")
        outcomes = set()
        for mode, at, accuracy in product(("fresh", "listed", "unlisted"), (0, 3, 4, 5), (0, 1)):
            event = _exposure("use", at, before=1)
            captures = [
                _capture(
                    "cover",
                    -1,
                    5,
                    accuracy=accuracy,
                    entries=(_typed(event),) if mode == "listed" else (),
                )
            ]
            if mode == "unlisted":
                captures.append(event)
            result = assess(
                bind(
                    _request(
                        _USES[3],
                        "no_prelock_exposure",
                        "history",
                        captures,
                        tuple(captures),
                        margin=accuracy,
                    )
                ),
                solver,
            )
            outcome = result["findings"][0]["outcome"]
            outcomes.add(outcome)
            if outcome != "passed":
                continue
            readings = {-1, 5}
            if mode == "listed":
                readings.update((at - 1, at))
            worlds = []
            for times in _clock_maps({"clock": readings}, accuracy):
                lo, hi = times["clock", -1], times["clock", 5]
                if mode == "listed":
                    possibilities = range(times["clock", at - 1], times["clock", at] + 1)
                    worlds.extend(possibilities)
                else:
                    possibilities = (
                        range(-4, 13) if mode == "fresh" else range(2 * (at - 1), 2 * at + 1)
                    )
                    worlds.extend(t for t in possibilities if not lo <= t < hi)
            with self.subTest(mode=mode, at=at, accuracy=accuracy):
                self.assertEqual(result["clock_compatibility"], "compatible")
                self.assertTrue(worlds)
                self.assertTrue(all(not 0 <= t < 8 for t in worlds))
        self.assertEqual(outcomes, {"passed", "failed", "cantTell"})

    def test_positive_calibration_can_witness_joint_omission(self) -> None:
        """A cross-channel reading constrains only the clock it actually names."""
        solver = shutil.which("clockcheck")
        self.assertIsNotNone(solver, "install the Clockcheck test dependency")
        left = _capture("left", -2, 2, accuracy=1)
        right = _capture("right", 2, 3, accuracy=1)
        use = _exposure("unlisted", 2)
        anchor = _exposure("anchor", 3, channel="network")

        def result(
            reports: list[dict[str, Any]], accepted: tuple[dict[str, Any], ...]
        ) -> dict[str, Any]:
            return assess(
                bind(_request(_USES[3], "coverage", "history", reports, accepted, margin=1)),
                solver,
            )

        for status, shared in product(("incomplete", "disabled", "unknown"), (False, True)):
            calibration = _capture(
                "calibration",
                2,
                4,
                accuracy=1,
                status=status,
                channel="network",
                clock="clock" if shared else "separate",
                entries=(_typed(anchor),),
            )
            reports = [left, right, use, anchor, calibration]

            original = result(reports, tuple(reports))
            witnesses = original["coverage"][0]["window"]["joint_omissions"]
            with self.subTest(status=status, shared=shared):
                self.assertEqual(
                    original["consistency"], "inconsistent" if shared else "consistent"
                )
                self.assertEqual(original["findings"][0]["outcome"], "cantTell")
                self.assertEqual(len(witnesses), int(shared))
                if shared:
                    self.assertEqual(set(witnesses[0]["unit_ids"]), {left["id"], right["id"]})
                    omitted = next(
                        reason
                        for reason in original["inconsistencies"]
                        if reason["code"] == "omitted_event"
                    )
                    self.assertLessEqual(
                        {anchor["id"], calibration["id"]}, set(omitted["report_ids"])
                    )
                    for removed in (use, anchor, calibration):
                        reduced = result(
                            reports, tuple(report for report in reports if report != removed)
                        )
                        self.assertEqual(reduced["consistency"], "consistent")
                        self.assertEqual(reduced["coverage"][0]["window"]["joint_omissions"], [])
