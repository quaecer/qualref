# SPDX-License-Identifier: Apache-2.0
"""Check the boundary between a clock formula and a returned certificate."""

import unittest
from fractions import Fraction

from quaecer.qualref.clock_problem import Bound, ClockCheck, _response


class ClockCertificateTest(unittest.TestCase):
    def test_strict_rational_assignment_is_checked(self) -> None:
        """Accept an assignment strictly within both submitted bounds."""
        problem = ((Bound("x", limit=1, strict=True),), (Bound(None, "x", 0, True),))
        valid = _response(b'{"status":"compatible","assignment":{"x":"1/2"}}', problem)
        self.assertEqual(valid.status, "compatible")
        self.assertEqual(valid.assignment, (("x", Fraction(1, 2)),))
        for received in (
            b'{"status":"compatible","assignment":{"x":"1"}}',
            b'{"status":"compatible","assignment":{"x":"0"}}',
            b'{"status":"compatible","assignment":{"a":"1/2"}}',
        ):
            with self.subTest(received=received):
                self.assertEqual(_response(received, problem).status, "unresolved")

    def test_unavailable_clock_solver_preserves_unknown(self) -> None:
        """The empty formula is feasible without a clock solver."""
        checker = ClockCheck(None)
        self.assertEqual(checker.solve(()).status, "compatible")
        self.assertEqual(checker.solve(((Bound("x"),),)).status, "unresolved")

    def test_refuses_a_conflict_outside_the_submitted_formula(self) -> None:
        """Bound the indices of a trusted solver's claimed incompatible subset."""
        problem = ((Bound("x"),), (Bound(None, "x", -1),))
        self.assertEqual(
            _response(b'{"status":"incompatible","clauses":[0,1]}', problem).status,
            "incompatible",
        )
        self.assertEqual(
            _response(b'{"status":"incompatible","clauses":[0,2]}', problem).status,
            "unresolved",
        )
