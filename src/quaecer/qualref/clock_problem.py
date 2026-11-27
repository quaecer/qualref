# SPDX-License-Identifier: Apache-2.0
"""Exact, portable difference bounds and the clockcheck process adapter."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from time import monotonic
from typing import Literal

type Status = Literal["compatible", "incompatible", "unresolved"]


@dataclass(frozen=True)
class Bound:
    """Constrain left minus right by limit. None denotes the fixed zero."""

    left: str | None
    right: str | None = None
    limit: int = 0
    strict: bool = False

    def wire(self) -> dict[str, str | bool | None]:
        return {
            "left": self.left,
            "right": self.right,
            "limit": str(self.limit),
            "strict": self.strict,
        }

    def holds(self, values: dict[str | None, Fraction]) -> bool:
        difference = values[self.left] - values[self.right]
        return difference < self.limit if self.strict else difference <= self.limit


type Clause = tuple[Bound, ...]
type Problem = tuple[Clause, ...]


@dataclass(frozen=True)
class Check:
    status: Status
    assignment: tuple[tuple[str, Fraction], ...] = ()
    conflict: tuple[int, ...] = ()


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate clockcheck response fields")
    return fields


def _response(raw: bytes, problem: Problem) -> Check:
    response: object = json.loads(raw, object_pairs_hook=_unique_fields)
    if not isinstance(response, dict):
        return Check("unresolved")
    if response.keys() == {"status", "clauses"} and response["status"] == "incompatible":
        indices = response["clauses"]
        if (
            isinstance(indices, list)
            and indices
            and all(type(index) is int and 0 <= index < len(problem) for index in indices)
            and len(indices) == len(set(indices))
        ):
            return Check("incompatible", conflict=tuple(indices))
        return Check("unresolved")
    if response.keys() != {"status", "assignment"} or response["status"] != "compatible":
        return Check("unresolved")
    variables = {
        name
        for clause in problem
        for bound in clause
        for name in (bound.left, bound.right)
        if name is not None
    }
    assignment = response["assignment"]
    if not isinstance(assignment, dict) or assignment.keys() != variables:
        return Check("unresolved")
    values: dict[str | None, Fraction] = {None: Fraction(0)}
    for name in sorted(variables):
        value = assignment[name]
        if not isinstance(value, str) or not re.fullmatch(r"-?[0-9]+(?:/[1-9][0-9]*)?", value):
            return Check("unresolved")
        values[name] = Fraction(value)
    if not all(any(bound.holds(values) for bound in clause) for clause in problem):
        return Check("unresolved")
    return Check("compatible", assignment=tuple((name, values[name]) for name in sorted(variables)))


class ClockCheck:
    """Bound process time across one assessment and retain distinct SAT and UNSAT evidence."""

    def __init__(self, executable: str | None) -> None:
        self.executable = Path(executable).absolute() if executable else None
        self.remaining_seconds = 4.0
        self.remaining_calls = 256

    def solve(self, problem: Problem) -> Check:
        if not problem:
            return Check("compatible")
        if self.executable is None or self.remaining_seconds <= 0 or self.remaining_calls <= 0:
            return Check("unresolved")
        payload = {
            "format": "clock-problem@1",
            "clauses": [[bound.wire() for bound in clause] for clause in problem],
        }
        self.remaining_calls -= 1
        before = monotonic()
        try:
            completed = subprocess.run(
                [str(self.executable)],
                input=json.dumps(payload, separators=(",", ":")).encode("ascii"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=min(2.0, self.remaining_seconds),
                check=True,
            )
            return _response(completed.stdout, problem)
        except (OSError, ValueError, subprocess.SubprocessError):
            return Check("unresolved")
        finally:
            self.remaining_seconds -= monotonic() - before
