# SPDX-License-Identifier: Apache-2.0
"""Invented examples for qualification wire binding and transfer."""

from __future__ import annotations

import unittest
from collections.abc import Sequence
from copy import deepcopy
from typing import Any

from quaecer.qualref.transfer import carry
from quaecer.qualref.wire import (
    BASE,
    Catalogue,
    View,
    basis,
    bind,
    canonical,
    digest,
    parse,
    reason,
)

START = "2025-03-09T10:00:00Z"
END = "2025-03-09T11:00:00Z"


def pin(name: str) -> dict[str, str]:
    return {"id": "urn:example:" + name, "digest": digest(name)}


def envelope(kind: str = "original", names: Sequence[str] = ("quality",)) -> dict[str, Any]:
    use = "urn:example:use-" + kind
    registry = {
        "format": "qualification-use-registry@1",
        "uses": ["original", "mid", "receiving"],
        "edges": [
            {"target": "receiving", "source": "mid"},
            {"target": "mid", "source": "original"},
        ],
        "closure": "reflexive_transitive",
        "instance_relation": "canonical_semantic_equality",
    }
    registry_digest = digest(registry)
    policy = {
        "profile": BASE + "policy",
        "use": {
            "id": use,
            "kind": kind,
            "question": "Does the sample meet the cutoff?",
            "claim": pin("claim"),
            "scope": "one sample",
        },
        "use_registry_digest": registry_digest,
        "subject": pin("sample"),
        "implementation": pin("measurement"),
        "window": {"start": START, "end": END},
        "history_scope": {"start": START},
        "lock_at": END,
        "channels": ["context"],
        "forbidden": [],
        "rules": [
            {
                "id": name,
                "operator": "control",
                "criterion": "sample reading",
                "uses": [kind],
                "expected": "0.50" if kind == "original" else "5e-1",
                "tolerance": "+0.025" if kind == "original" else "25e-3",
                "unit": "kg",
            }
            for name in names
        ],
        "conflict_policy": "sceptical",
        "scope_margin_us": 0,
        "defeat_scope": "segment",
    }
    policy_digest = digest(policy)
    observation = {
        "id": "urn:example:reading",
        "kind": "control",
        "issuer": pin("lab"),
        "subject": pin("sample"),
        "implementation": pin("measurement"),
        "basis": [pin("instrument")],
        "criterion": "sample reading",
        "unit": "kg",
        "state": "ran",
        "observed": "0.525",
    }
    evidence = {
        "profile": BASE + "evidence",
        "use": use,
        "policy_digest": policy_digest,
        "subject": pin("sample"),
        "implementation": pin("measurement"),
        "claim": pin("claim"),
        "references": [
            pin(name) for name in ("sample", "measurement", "claim", "lab", "instrument")
        ],
        "reports": [observation],
    }
    return {
        "profile": BASE + "request",
        "operation": "assess",
        "policy": policy,
        "evidence": evidence,
        "use_registry": registry,
        "caller": {
            "use": use,
            "subject": pin("sample"),
            "implementation": pin("measurement"),
            "policy_digest": policy_digest,
            "use_registry_digest": registry_digest,
            "report_pins": [{"id": observation["id"], "digest": digest(observation)}],
            "bodies": [],
        },
    }


def confirm(view: View) -> dict[str, Any]:
    """Supply independent definite findings to test the transfer boundary."""
    return {
        "clock_compatibility": "compatible",
        "consistency": "consistent",
        "qualification": "prerequisites_satisfied",
        "authorization": "not_granted",
        "findings": [
            {
                "criterion": rule["id"],
                "execution": "evaluated",
                "value": "support",
                "outcome": "passed",
                "reasons": [reason("unavailable_report", criterion=rule["id"])],
                "basis": basis(view, view.selected),
            }
            for rule in view.policy["rules"]
        ],
        "transfers": [],
    }


class WireTest(unittest.TestCase):
    def test_integer_only_utf16_canonical_json(self) -> None:
        value = parse(rb'{"\ue000":0,"\ud800\udc00":-0,"a":"\u0000\n"}')
        self.assertEqual(canonical(value), '{"a":"\\u0000\\n","𐀀":0,"":0}'.encode())
        for invalid in (
            b'{"a":0,"a":1}',
            b"9007199254740992",
            b"-9007199254740992",
            b"1.0",
            b"1e2",
            b"NaN",
            b'"\\ud800"',
            b'"\xff"',
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse(invalid)

    def test_frozen_schema_recognizes_variant_and_ref_siblings(self) -> None:
        catalogue = Catalogue()
        request = envelope()
        self.assertTrue(catalogue.accepts("request", request))
        self.assertIn("@vocab", catalogue.context("evidence"))
        request["evidence"]["reports"][0]["state"] = "not_run"
        self.assertFalse(catalogue.accepts("request", request))
        request["evidence"]["reports"][0]["observed"] = None
        self.assertTrue(catalogue.accepts("request", request))
        transfer = {
            "profile": BASE + "transfer-request",
            "operation": "transfer",
            "source": request,
            "target": envelope("receiving"),
        }
        self.assertTrue(catalogue.accepts("transfer-request", transfer))
        request["operation"] = "validate"
        self.assertFalse(catalogue.accepts("transfer-request", transfer))

    def test_acceptance_binds_actual_selected_report(self) -> None:
        request = envelope()
        first = bind(request)
        report_id = "urn:example:reading"
        self.assertEqual(list(first.selected), [report_id])
        self.assertEqual(len(basis(first, [report_id, report_id])), 2)
        request["evidence"]["references"].reverse()
        self.assertEqual(first.view_digest, bind(request).view_digest)
        request["evidence"]["reports"][0]["observed"] = "0.60"
        with self.assertRaises(ValueError):
            bind(request)
        request["caller"]["report_pins"] = []
        second = bind(request)
        self.assertEqual(list(second.reports), [report_id])
        self.assertEqual(second.selected, {})
        self.assertNotEqual(first.view_digest, second.view_digest)

    def test_wrong_payload_is_premise_but_noncanonical_base64_is_refused(self) -> None:
        request = envelope()
        artifact = pin("artifact")
        request["evidence"]["references"].append(artifact)
        request["caller"]["bodies"] = [{"artifact": artifact, "bytes_base64": "YQ=="}]
        self.assertEqual(bind(request).bodies, {canonical(artifact): b"a"})
        request["caller"]["bodies"][0]["bytes_base64"] = "YR=="
        with self.assertRaises(ValueError):
            bind(request)

    def test_partition_compares_instants_and_checks_selected_commitments(self) -> None:
        request = envelope()
        start_midpoint = "2025-03-09T10:30:00Z"
        end_midpoint = "2025-03-09T12:30:00+02:00"
        report = {
            **request["evidence"]["reports"][0],
            "id": "urn:example:capture",
            "kind": "completeness",
            "interval": {"start": START, "end": END},
            "entries": [],
            "inventory_digest": None,
            "segments": [
                {
                    "id": "urn:example:late",
                    "interval": {"start": end_midpoint, "end": END},
                    "entries": [],
                    "inventory_digest": digest([]),
                },
                {
                    "id": "urn:example:early",
                    "interval": {"start": START, "end": start_midpoint},
                    "entries": [],
                    "inventory_digest": digest([]),
                },
            ],
        }
        request["evidence"]["reports"].append(report)
        selection = {"id": report["id"], "digest": digest(report)}
        request["caller"]["report_pins"].append(selection)
        self.assertIn(report["id"], bind(request).selected)
        report["segments"][0]["interval"]["start"] = "2025-03-09T12:31:00+02:00"
        selection["digest"] = digest(report)
        with self.assertRaises(ValueError):
            bind(request)

    def test_carry_binds_original_finding_and_relabels_reasons(self) -> None:
        source = bind(envelope(names=("zeta", "alpha")))
        target = bind(envelope("receiving", ("receiver-check",)))
        result = carry(source, target, confirm)
        self.assertEqual(result["findings"][0]["reasons"][0]["criterion"], "receiver-check")
        certificate = result["transfers"][0]
        self.assertEqual(certificate["source_criterion"], "alpha")
        self.assertEqual(
            certificate["source_finding_digest"], digest(confirm(source)["findings"][1])
        )
        self.assertEqual(
            certificate["criterion_digest"],
            digest(
                {
                    "profile": BASE + "criterion-instance",
                    "predicate": {
                        "operator": "control",
                        "criterion": "sample reading",
                        "expected": "1/2",
                        "tolerance": "1/40",
                        "unit": "kg",
                    },
                    "settings": {"conflict_policy": "sceptical"},
                }
            ),
        )
        self.assertEqual(result["qualification"], "prerequisites_satisfied")
        with self.assertRaises(ValueError):
            carry(target, source, confirm)

    def test_unresolved_source_leaves_target_intact(self) -> None:
        source = bind(envelope())
        target = bind(envelope("receiving"))

        def direct(view: View) -> dict[str, Any]:
            result = deepcopy(confirm(view))
            if view is source:
                result["clock_compatibility"] = "unresolved"
            return result

        self.assertEqual(carry(source, target, direct), direct(target))


if __name__ == "__main__":
    unittest.main()
