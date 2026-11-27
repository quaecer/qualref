# SPDX-License-Identifier: Apache-2.0
"""Interpret accepted capture commitments, occurrence identities, and timing."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .clock_problem import Bound, Check, Clause, ClockCheck, Problem
from .wire import View, basis, canonical, digest, instant, reason

type Record = dict[str, Any]
type Span = tuple[int, int]
type Envelope = tuple[int | None, int | None]
type Resource = tuple[str, str]
type Reading = tuple[str, int]
type Affected = tuple[str, str]

# Integral coordinates count UTC microseconds from the earliest wire instant.
_EPOCH = datetime(1, 1, 1, tzinfo=UTC)
_TICK = timedelta(microseconds=1)
_LAST = (datetime.max.replace(tzinfo=UTC) - _EPOCH) // _TICK


def _time(value: str) -> int:
    return (instant(value) - _EPOCH) // _TICK


def _at(value: int) -> str:
    return (_EPOCH + value * _TICK).isoformat().replace("+00:00", "Z")


def _span(interval: Record) -> Span:
    start, end = _time(interval["start"]), _time(interval["end"])
    if start >= end:
        raise ValueError("empty or reversed capture scope")
    return start, end


def _interval(span: Span) -> dict[str, str]:
    return {"start": _at(span[0]), "end": _at(span[1])}


def _pin(value: Record) -> Resource:
    return value["id"], value["digest"]


def _bound(value: int | None) -> int | None:
    return value if value is not None and 0 <= value <= _LAST else None


def _observed_bounds(data: Record) -> Envelope:
    if data["at"] is None:
        return None, None
    nominal = _time(data["at"])
    before, after = data["uncertainty_before_us"], data["uncertainty_after_us"]
    if before is None or after is None:
        return None, None
    lower, upper = _bound(nominal - before), _bound(nominal + after)
    return (lower, upper) if lower is not None and upper is not None else (None, None)


def _ordered(rows: list[Record]) -> list[Record]:
    unique = {canonical(row): row for row in rows}
    return [unique[key] for key in sorted(unique)]


@dataclass(frozen=True)
class Unit:
    id: str
    report: str
    observer: str
    channels: tuple[str, ...]
    span: Span
    clock: str
    accuracy: int | None
    status: str
    scheme: str | None
    entries: tuple[Record, ...]


def _units(view: View) -> list[Unit]:
    units: list[Unit] = []
    for report_id, report in view.selected.items():
        if report["kind"] != "completeness":
            continue
        for part in report["segments"] or [report]:
            units.append(
                Unit(
                    part["id"],
                    report_id,
                    report["observer"],
                    tuple(report["channels"]),
                    _span(part["interval"]),
                    report["clock_id"],
                    report["accuracy_us"],
                    report["status"],
                    report["identity_scheme"],
                    tuple(part["entries"]),
                )
            )
    return sorted(units, key=lambda unit: unit.id)


@dataclass(frozen=True)
class Observation:
    id: str
    report: str
    channel: str
    resource: Resource
    identity: str | None
    canonical_id: str | None
    aliases: tuple[str, ...]
    bracket: Envelope
    clock: str | None
    accuracy: int | None
    usage_digest: str
    unit: str | None

    @property
    def descriptor(self) -> tuple[str, Resource]:
        return self.channel, self.resource


@dataclass(frozen=True)
class Event:
    name: str
    observations: tuple[Observation, ...]
    reports: tuple[str, ...]
    channel: str
    resource: Resource
    canonical_id: str | None


@dataclass(frozen=True)
class Occurrences:
    events: list[Event]
    listed: dict[str, set[str]]
    unresolved: bool
    unusable_units: set[str]
    reasons: list[Record]
    conflicts: list[Record]


def _observation(
    identifier: str,
    report: str,
    data: Record,
    scheme: str | None,
    clock: str | None,
    accuracy: int | None,
    usage_digest: str,
    unit: str | None = None,
) -> Observation:
    identity = data["occurrence_id"]
    return Observation(
        identifier,
        report,
        data["channel"],
        _pin(data["resource"]),
        identity,
        identity if scheme is not None else None,
        tuple(data["same_as"]),
        _observed_bounds(data),
        clock,
        accuracy,
        usage_digest,
        unit,
    )


class _Groups:
    def __init__(self, size: int) -> None:
        self.parents = list(range(size))

    def root(self, index: int) -> int:
        while self.parents[index] != index:
            self.parents[index] = self.parents[self.parents[index]]
            index = self.parents[index]
        return index

    def join(self, first: int, second: int) -> None:
        first, second = sorted((self.root(first), self.root(second)))
        self.parents[second] = first


def _occurrences(view: View, units: list[Unit]) -> Occurrences:
    observations = [
        _observation(
            identifier,
            identifier,
            report,
            report["identity_scheme"],
            None,
            None,
            view.pins[identifier]["digest"],
        )
        for identifier, report in sorted(view.selected.items())
        if report["kind"] == "exposure"
    ]
    for unit in units:
        for entry in unit.entries:
            if entry["kind"] == "typed":
                if entry["channel"] not in unit.channels:
                    raise ValueError("typed entry channel lies outside the commitment")
                observations.append(
                    _observation(
                        entry["event_id"],
                        unit.report,
                        entry,
                        unit.scheme,
                        unit.clock,
                        unit.accuracy,
                        entry["usage_digest"],
                        unit.id,
                    )
                )

    by_id: dict[str, list[int]] = defaultdict(list)
    for index, observation in enumerate(observations):
        by_id[observation.id].append(index)
    groups = _Groups(len(observations))
    conflicts = []
    conflicted: set[str] = set()
    canonical_ids: dict[tuple[tuple[str, Resource], str], int] = {}
    for identifier, indices in sorted(by_id.items()):
        members = [observations[index] for index in indices]
        descriptors = {(member.descriptor, member.usage_digest) for member in members}
        tokens = {member.canonical_id for member in members} - {None}
        if len(descriptors) != 1 or len(tokens) > 1:
            conflicted.add(identifier)
            conflicts.append(
                reason("conflicting_observations", reports=(m.report for m in members))
            )
            continue
        for index in indices:
            groups.join(indices[0], index)
            observation = observations[index]
            if observation.canonical_id is not None:
                key = observation.descriptor, observation.canonical_id
                groups.join(index, canonical_ids.setdefault(key, index))

    unresolved = bool(conflicted)
    # Check aliases between exact descriptors before considering the effect of a chain.
    candidate_groups = _Groups(len(observations))
    alias_links: list[tuple[int, int]] = []
    for identifier, indices in sorted(by_id.items()):
        disputes: set[str] = set()
        if identifier in conflicted:
            continue
        for index in indices:
            observation = observations[index]
            for alias in observation.aliases:
                if alias not in by_id or alias in conflicted:
                    unresolved = True
                    continue
                targets = [observations[target] for target in by_id[alias]]
                if any(
                    other.descriptor != observation.descriptor
                    or (
                        observation.canonical_id is not None
                        and other.canonical_id is not None
                        and observation.canonical_id != other.canonical_id
                    )
                    for other in targets
                ):
                    disputes.update((observation.report, *(target.report for target in targets)))
                    continue
                source, destination = groups.root(index), groups.root(by_id[alias][0])
                candidate_groups.join(source, destination)
                alias_links.append((source, destination))
        if disputes:
            conflicts.append(reason("conflicting_observations", reports=disputes))

    proposed: dict[int, list[Observation]] = defaultdict(list)
    for index, observation in enumerate(observations):
        if observation.id not in conflicted:
            proposed[candidate_groups.root(groups.root(index))].append(observation)
    rejected: set[int] = set()
    for component, members in proposed.items():
        if len({member.canonical_id for member in members} - {None}) > 1:
            rejected.add(component)
            conflicts.append(
                reason("conflicting_observations", reports=(m.report for m in members))
            )
    for source, destination in alias_links:
        if candidate_groups.root(source) not in rejected:
            groups.join(source, destination)

    partition: dict[int, list[Observation]] = defaultdict(list)
    for index, observation in enumerate(observations):
        if (
            observation.id not in conflicted
            and candidate_groups.root(groups.root(index)) not in rejected
        ):
            partition[groups.root(index)].append(observation)
    events: dict[int, Event] = {}
    for component, members in sorted(partition.items()):
        representative = members[0]
        events[component] = Event(
            f"event-{component}",
            tuple(members),
            tuple(sorted({member.report for member in members})),
            representative.channel,
            representative.resource,
            next(
                (member.canonical_id for member in members if member.canonical_id is not None),
                None,
            ),
        )

    listed: dict[str, set[str]] = {}
    missing: list[Record] = []
    unusable: set[str] = set()
    for unit in units:
        found: set[str] = set()
        unavailable: set[str] = set()
        for entry in unit.entries:
            identifier = entry["event_id"]
            roots = {groups.root(index) for index in by_id.get(identifier, [])}
            event = events.get(next(iter(roots))) if len(roots) == 1 else None
            if event is None or event.channel not in unit.channels:
                unavailable.add(identifier)
            else:
                found.add(event.name)
        listed[unit.id] = found
        if unavailable:
            unusable.add(unit.id)
            missing.append(reason("missing_usage", reports=(unit.report,), related=unavailable))
    return Occurrences(
        list(events.values()), listed, unresolved or bool(unusable), unusable, missing, conflicts
    )


@dataclass(frozen=True)
class Positive:
    clauses: Problem
    readings: dict[Reading, str]
    reports: set[str]
    complete: bool
    clock_constraints: list[Record]


def _maximum(values: list[int | None]) -> int | None:
    return max((value for value in values if value is not None), default=None)


def _minimum(values: list[int | None]) -> int | None:
    return min((value for value in values if value is not None), default=None)


def _positive(
    units: list[Unit], events: list[Event], unresolved: bool, pins: dict[str, Record]
) -> Positive:
    clock_readings: dict[str, set[int]] = defaultdict(set)
    bands: dict[str, set[tuple[int, int, int]]] = defaultdict(set)
    reports: set[str] = set()
    clock_constraints: list[Record] = []
    complete = not unresolved
    for unit in units:
        start, end = unit.span
        clock_readings[unit.clock].update(unit.span)
        if unit.accuracy is not None:
            bands[unit.clock].add((start, end, unit.accuracy))
            clock_constraints.append(
                {
                    "kind": "capture_accuracy",
                    "report": pins[unit.report],
                    "unit": unit.id,
                    "observer": unit.observer,
                    "clock_id": unit.clock,
                    "lower": _at(start),
                    "upper": _at(end),
                    "accuracy_us": unit.accuracy,
                }
            )
            reports.add(unit.report)
        else:
            complete = False
    for event in events:
        reports.update(event.reports)
        for observation in event.observations:
            lower, upper = observation.bracket
            if lower is None or upper is None:
                complete = False
            clock = observation.clock
            if clock is not None:
                clock_readings[clock].update(
                    reading for reading in observation.bracket if reading is not None
                )
                if observation.accuracy is not None and lower is not None and upper is not None:
                    bands[clock].add((lower, upper, observation.accuracy))

    clauses: list[Clause] = []
    readings: dict[Reading, str] = {}
    for clock, nominal_readings in sorted(clock_readings.items()):
        previous: str | None = None
        for nominal in sorted(nominal_readings):
            variable = readings[clock, nominal] = f"reading-{len(readings)}"
            if previous is not None:
                clauses.append((Bound(previous, variable),))
            previous = variable
            error = min(
                (accuracy for start, end, accuracy in bands[clock] if start <= nominal <= end),
                default=None,
            )
            if error is not None:
                clauses.extend(
                    (
                        (Bound(None, variable, error - nominal),),
                        (Bound(variable, None, nominal + error),),
                    )
                )
    for event in events:
        occurrence = min(observation.id for observation in event.observations)
        for observation in event.observations:
            lower, upper = observation.bracket
            clock = observation.clock
            if lower is None or upper is None:
                continue
            description = {
                "report": pins[observation.report],
                "event_id": observation.id,
                "occurrence": occurrence,
                "lower": _at(lower),
                "upper": _at(upper),
            }
            if clock is None:
                clauses.extend(
                    ((Bound(None, event.name, -lower),), (Bound(event.name, None, upper),))
                )
                clock_constraints.append({"kind": "event_utc", **description})
            elif observation.accuracy is not None:
                clauses.extend(
                    (
                        (Bound(readings[clock, lower], event.name),),
                        (Bound(event.name, readings[clock, upper]),),
                    )
                )
                clock_constraints.append(
                    {
                        "kind": "entry_clock",
                        **description,
                        "clock_id": clock,
                        "unit": observation.unit,
                        "accuracy_us": observation.accuracy,
                    }
                )
    return Positive(
        tuple(dict.fromkeys(clauses)), readings, reports, complete, _ordered(clock_constraints)
    )


@dataclass(frozen=True)
class Temporal:
    """Temporal decisions retained for one accepted view."""

    clock_compatibility: str
    coverage: list[Record]
    inconsistencies: list[Record]
    findings: dict[str, Record]
    clock_constraints: list[Record]


def _declared_envelope(observation: Observation) -> Envelope:
    a, b = observation.bracket
    if observation.clock is None:
        return a, b
    if observation.accuracy is None:
        return None, None
    return (
        a - observation.accuracy if a is not None else None,
        b + observation.accuracy if b is not None else None,
    )


def _event_envelope(event: Event) -> Envelope:
    boxes = [_declared_envelope(item) for item in event.observations]
    return _maximum([a for a, _ in boxes]), _minimum([b for _, b in boxes])


def _separate(first: Event, second: Event) -> bool:
    if first.resource != second.resource or first.channel != second.channel:
        return True
    if first.canonical_id is not None and second.canonical_id is not None:
        return first.canonical_id != second.canonical_id
    a, b = _event_envelope(first)
    c, d = _event_envelope(second)
    return (b is not None and c is not None and b < c) or (
        a is not None and d is not None and d < a
    )


def _window_membership(event: Event, interval: Span) -> Problem:
    a, b = interval
    return ((Bound(None, event.name, -a),), (Bound(event.name, limit=b, strict=True),))


def _outside_window(event: Event, interval: Span) -> Clause:
    a, b = interval
    return (Bound(event.name, limit=a, strict=True), Bound(None, event.name, -b))


def _inside(box: Envelope, window: Span) -> bool:
    a, b = box
    return a is not None and b is not None and window[0] <= a <= b < window[1]


def _can_meet(box: Envelope, interval: Span) -> bool:
    a, b = box
    return (b is None or interval[0] <= b) and (a is None or a < interval[1])


def _nominal(unit: Unit, extra: int = 0) -> Span:
    return unit.span[0] - extra, unit.span[1] + extra


def _clock_interval(unit: Unit, positive: Positive) -> tuple[str, str]:
    a, b = unit.span
    return positive.readings[unit.clock, a], positive.readings[unit.clock, b]


def _commitment_clauses(
    observations: Occurrences,
    units: list[Unit],
    positive: Positive,
) -> dict[str, list[tuple[Unit, Clause]]]:
    events = {event.name: event for event in observations.events}
    clauses: dict[str, list[tuple[Unit, Clause]]] = defaultdict(list)
    for event in observations.events:
        for unit in units:
            if event.channel not in unit.channels or event.name in observations.listed[unit.id]:
                continue
            if not _can_meet(_event_envelope(event), _nominal(unit, unit.accuracy or 0)):
                continue
            if not all(_separate(event, events[name]) for name in observations.listed[unit.id]):
                continue
            a, b = _clock_interval(unit, positive)
            clauses[event.name].append(
                (
                    unit,
                    (Bound(event.name, a, strict=True), Bound(b, event.name)),
                )
            )
    return clauses


def _widen(unit: Unit, channel: str, units: list[Unit], scope: str) -> set[Affected]:
    if scope == "segment":
        return {(unit.id, channel)}
    if scope == "statement":
        return {
            (other.id, member)
            for other in units
            if other.report == unit.report
            for member in other.channels
        }
    return {
        (other.id, member)
        for other in units
        if other.observer == unit.observer and other.status == "complete"
        for member in other.channels
        if scope == "observer" or member == channel
    }


type Region = tuple[int, int, frozenset[str]]
type Support = tuple[Span, Record]


def _merge(items: list[Region]) -> list[Region]:
    """Merge connected half-open regions, retaining the contributing identifiers."""
    merged: list[Region] = []
    for a, b, names in sorted(items, key=lambda row: (row[0], row[1], sorted(row[2]))):
        if a >= b:
            continue
        if merged and a <= merged[-1][1]:
            first, last, contributors = merged.pop()
            merged.append((first, max(last, b), contributors | names))
        else:
            merged.append((a, b, names))
    return merged


def _guaranteed(units: list[Unit], margin: int) -> list[Support]:
    interiors = []
    lookup = {unit.id: unit for unit in units}
    for clock in sorted({unit.clock for unit in units}):
        nominal = _merge(
            [(*unit.span, frozenset({unit.id})) for unit in units if unit.clock == clock]
        )
        for a, b, names in nominal:
            if a + margin < b - margin:
                interiors.append(
                    (
                        (a + margin, b - margin),
                        dict(
                            clock_id=clock,
                            lower=_at(a),
                            upper=_at(b),
                            accuracy_us=max(lookup[name].accuracy or 0 for name in names),
                            erosion_us=margin,
                            observers=sorted({lookup[name].observer for name in names}),
                            unit_ids=sorted(names),
                        ),
                    )
                )
    return interiors


def _composition(
    target: Span,
    supports: list[Support],
    defeated: list[Region],
    statements: list[dict[str, str]],
    reasons: list[Record],
    witnesses: list[Record],
) -> Record:
    start, end = target

    def clip(rows: list[Region]) -> list[Region]:
        return _merge([(max(a, start), min(b, end), ids) for a, b, ids in rows])

    def wire(rows: list[Region]) -> list[Record]:
        return [{"interval": _interval((a, b)), "unit_ids": sorted(ids)} for a, b, ids in rows]

    kept = clip([(*span, frozenset(proof["unit_ids"])) for span, proof in supports])
    edge = start
    gaps = []
    for a, b, _ in kept:
        if edge < a:
            gaps.append(_interval((edge, a)))
        edge = b
    if edge < end:
        gaps.append(_interval((edge, end)))
    return {
        "covered": wire(kept),
        "supports": _ordered(
            [
                dict(proof, interval=_interval((max(start, a), min(end, b))))
                for (a, b), proof in supports
                if max(start, a) < min(end, b)
            ]
        ),
        "gaps": gaps,
        "defeated": wire(clip(defeated)),
        "statements": statements,
        "reasons": _ordered(reasons),
        "joint_omissions": _ordered(witnesses),
    }


def _capture_disputes(
    view: View,
    solver: ClockCheck,
    units: list[Unit],
    eligible: list[Unit],
    positive: Positive,
    affected: set[Affected],
) -> tuple[list[Record], bool]:
    notes = []
    unresolved = False
    policy = view.policy
    for unit in eligible:
        a, b = _clock_interval(unit, positive)
        possible = _nominal(unit, unit.accuracy or 0)
        for channel in sorted(unit.channels):
            status_reports = set()
            for other in units:
                if (
                    other.observer != unit.observer
                    or other.status not in ("incomplete", "disabled")
                    or channel not in other.channels
                    or other.accuracy is None
                ):
                    continue
                lo, hi = _nominal(other, other.accuracy)
                if possible[1] <= lo or hi <= possible[0]:
                    continue
                c, d = _clock_interval(other, positive)
                disjoint: Clause = (Bound(b, c), Bound(d, a), Bound(b, a), Bound(d, c))
                verdict = solver.solve((*positive.clauses, disjoint)).status
                if verdict == "incompatible":
                    status_reports.add(other.report)
                unresolved |= verdict == "unresolved"
            challenge_reports = set()
            for identifier, report in sorted(view.selected.items()):
                if report["kind"] not in ("capture_challenge", "channel_scope_challenge"):
                    continue
                if (
                    report.get("about_observer", unit.observer) != unit.observer
                    or report["channel"] != channel
                ):
                    continue
                lo, hi = _span(report["interval"])
                if possible[1] <= lo or hi <= possible[0]:
                    continue
                disjoint = (Bound(b, limit=lo), Bound(None, a, -hi), Bound(b, a))
                verdict = solver.solve((*positive.clauses, disjoint)).status
                if verdict == "incompatible":
                    challenge_reports.add(identifier)
                unresolved |= verdict == "unresolved"
            for code, reports in (
                ("conflicting_observations", status_reports),
                ("capture_challenge", challenge_reports),
            ):
                if reports:
                    affected.update(_widen(unit, channel, units, policy["defeat_scope"]))
                    notes.append(
                        reason(
                            code,
                            reports=reports | {unit.report},
                            related=(unit.id,),
                            channel=channel,
                        )
                    )
    return notes, unresolved


def _clock_compatibility(
    solver: ClockCheck,
    facts: Occurrences,
    positive: Positive,
    omitted: dict[str, list[tuple[Unit, Clause]]],
    units: list[Unit],
    policy: Record,
    affected: set[Affected],
) -> tuple[Check, Check, Problem, dict[str, list[Record]], list[Record]]:
    local_conflicts = []
    for event in facts.events:
        a, b = _event_envelope(event)
        if a is not None and b is not None and b < a:
            local_conflicts.append(
                reason("clock_incompatible", reports=event.reports, channel=event.channel)
            )
    if local_conflicts:
        impossible = Check("incompatible")
        return impossible, impossible, (), {}, local_conflicts
    direct = solver.solve(positive.clauses)
    if direct.status != "compatible":
        notes = (
            [reason("clock_incompatible", reports=positive.reports)]
            if direct.status == "incompatible"
            else []
        )
        return direct, direct, (), {}, notes

    joint = (*positive.clauses, *(clause for entries in omitted.values() for _, clause in entries))
    full = solver.solve(joint) if omitted else direct
    witnesses: dict[str, list[Record]] = defaultdict(list)
    notes = []
    if full.status == "incompatible":
        premise_digest = digest(positive.clock_constraints)
        for event in facts.events:
            group = omitted.get(event.name, [])
            left, right = _event_envelope(event)
            if not group or _bound(left) is None or _bound(right) is None:
                continue
            assert left is not None and right is not None
            fragment = (*positive.clauses, *(clause for _, clause in group))
            if solver.solve(fragment).status != "incompatible":
                continue
            scopes = sorted(unit.id for unit, _ in group)
            defeat = set().union(
                *(_widen(unit, event.channel, units, policy["defeat_scope"]) for unit, _ in group)
            )
            affected.update(defeat)
            witnesses[event.channel].append(
                {
                    "lower": _at(left),
                    "upper": _at(right),
                    "report_ids": list(event.reports),
                    "occurrence": min(item.id for item in event.observations),
                    "clock_constraints_digest": premise_digest,
                    "unit_ids": scopes,
                    "defeat_scope": policy["defeat_scope"],
                    "defeated_units": [
                        {"unit": key, "channel": channel} for key, channel in sorted(defeat)
                    ],
                }
            )
            notes.append(
                reason(
                    "omitted_event", reports=positive.reports, related=scopes, channel=event.channel
                )
            )
        if not notes:
            notes.append(reason("clock_incompatible", reports=positive.reports))
    return direct, full, joint, witnesses, notes


def evaluate_temporal(view: View, clockcheck: str | None) -> Temporal:
    """Derive clock and coverage judgements from the accepted view."""
    solver = ClockCheck(clockcheck)
    policy = view.policy
    units = _units(view)
    facts = _occurrences(view, units)
    positive = _positive(
        units,
        facts.events,
        facts.unresolved
        or bool(facts.conflicts)
        or any(event.canonical_id is None for event in facts.events),
        view.pins,
    )
    notes = list(facts.reasons)
    eligible = []
    for unit in units:
        if unit.status != "complete":
            continue
        if (
            unit.id in facts.unusable_units
            or unit.scheme is None
            or unit.accuracy is None
            or unit.accuracy > policy["scope_margin_us"]
        ):
            notes.append(reason("statement_obligation", reports=(unit.report,), related=(unit.id,)))
        else:
            eligible.append(unit)
    omissions = _commitment_clauses(facts, eligible, positive) if not facts.conflicts else {}
    affected: set[Affected] = set()
    direct, joint, problem, witnesses, conflicts = _clock_compatibility(
        solver,
        facts,
        positive,
        omissions,
        units,
        policy,
        affected,
    )
    consistency = [*facts.conflicts, *conflicts]
    checked = joint.status
    if checked == "compatible" and not positive.complete:
        checked = "unresolved"
    if direct.status == "compatible":
        disputes, undecided = _capture_disputes(view, solver, units, eligible, positive, affected)
        consistency.extend(disputes)
        if undecided and checked == "compatible":
            checked = "unresolved"

    window = _span(policy["window"])
    history = (_time(policy["history_scope"]["start"]), _time(policy["lock_at"]))
    forbidden = {_pin(pin) for pin in policy["forbidden"]}
    hazards = [
        event
        for event in facts.events
        if event.resource in forbidden and event.channel in policy["channels"]
    ]
    observed_violations: set[tuple[str, ...]] = set()
    inferred = False
    for event in hazards:
        raw = _event_envelope(event)
        if direct.status == "compatible" and _inside(raw, history):
            observed_violations.add(event.reports)
        elif direct.status == "compatible" and _can_meet(raw, history):
            outside = solver.solve((*positive.clauses, _outside_window(event, history))).status
            if outside == "incompatible":
                observed_violations.add(event.reports)
                inferred = True
            elif outside == "unresolved" and checked == "compatible":
                checked = "unresolved"
        else:
            observed_violations.update(
                (item.report,)
                for item in event.observations
                if _inside(_declared_envelope(item), history)
            )

    possible: tuple[str, ...] = ()
    if checked == "compatible" and not observed_violations:
        for event in hazards:
            if not _can_meet(_event_envelope(event), history):
                continue
            in_history = solver.solve((*problem, *_window_membership(event, history))).status
            if in_history == "compatible":
                possible = event.reports
                break
            if in_history == "unresolved":
                checked = "unresolved"
                break

    coverage = []
    if units:
        for channel in sorted(policy["channels"]):
            members = [unit for unit in units if channel in unit.channels]
            guaranteed = _guaranteed(
                [
                    unit
                    for unit in eligible
                    if channel in unit.channels and (unit.id, channel) not in affected
                ],
                policy["scope_margin_us"],
            )
            defeated = [
                (*_nominal(unit, unit.accuracy), frozenset({unit.id}))
                for unit in members
                if (unit.id, channel) in affected and unit.accuracy is not None
            ]
            selected = {unit.report for unit in members}
            local = [r for r in notes if selected.intersection(r["report_ids"])]
            local.extend(r for r in consistency if r["channel"] == channel)
            params = (
                guaranteed,
                defeated,
                [view.pins[i] for i in sorted(selected)],
                local,
                witnesses.get(channel, []),
            )
            coverage.append(
                {
                    "channel": channel,
                    "window": _composition(window, *params),
                    "history": _composition(history, *params),
                }
            )

    findings: dict[str, Record] = {}
    for rule in policy["rules"]:
        operator, criterion = rule["operator"], rule["id"]
        if (
            operator not in ("coverage", "no_prelock_exposure")
            or policy["use"]["kind"] not in rule["uses"]
        ):
            continue
        channel = rule.get("channel")
        absence = operator == "no_prelock_exposure"
        relevant = (
            [r["history"] for r in coverage]
            if absence
            else [r["window"] for r in coverage if r["channel"] == channel]
        )
        pins = {pin["id"] for r in relevant for pin in r["statements"]}
        complete = bool(relevant) and all(not r["gaps"] for r in relevant)
        if absence and observed_violations:
            pins = {key for group in observed_violations for key in group}
            if inferred:
                pins.update(positive.reports)
            value, outcome = "opposition", "failed"
            reasons = [
                reason("forbidden_exposure", criterion=criterion, reports=group)
                for group in sorted(observed_violations)
            ]
        elif (
            checked == "compatible"
            and complete
            and not consistency
            and (not absence or (forbidden and not possible))
        ):
            value, outcome = "support", "passed"
            reasons = []
            if absence:
                pins.update(positive.reports)
        else:
            value, outcome = "neither", "cantTell"
            code = "clock_unresolved" if checked != "compatible" else "coverage_gap"
            reported: tuple[str, ...] = ()
            if absence and checked == "compatible" and complete:
                pins.update(positive.reports)
                if possible:
                    code, reported = "possible_exposure", possible
            reasons = [reason(code, criterion=criterion, channel=channel, reports=reported)]
        findings[criterion] = {
            "criterion": criterion,
            "execution": "evaluated",
            "value": value,
            "outcome": outcome,
            "reasons": _ordered(reasons),
            "basis": basis(view, pins),
        }
    return Temporal(checked, coverage, _ordered(consistency), findings, positive.clock_constraints)
