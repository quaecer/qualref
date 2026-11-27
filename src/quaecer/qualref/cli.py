# SPDX-License-Identifier: Apache-2.0
"""Offline JSON process interface for the qualification reference evaluator."""

import argparse
import shutil
import sys
from collections.abc import Sequence
from functools import partial
from pathlib import Path
from typing import Any

from .assessment import assess
from .transfer import carry
from .wire import BASE, LIMIT, Catalogue, bind, canonical, parse

Record = dict[str, Any]


def _plain(node: Any) -> Any:
    if node is None:
        raise ValueError("RDF frames use an explicit marker at null positions")
    if isinstance(node, list):
        return [_plain(member) for member in node]
    if not isinstance(node, dict):
        return node
    if node == {"@id": "qual:Null"}:
        return None
    if any(key.startswith("@") for key in node):
        raise ValueError("unexpected nested JSON-LD directive")
    return {key: _plain(value) for key, value in node.items()}


def _unframe(kind: str, frame: Any, catalogue: Catalogue) -> Record:
    if kind == "evidence":
        root_type, collection, member_type = "qual:Evidence", "reports", "qual:Observation"
    else:
        root_type, collection, member_type = "qual:Result", "findings", "earl:TestResult"

    context = catalogue.context(kind)
    if not isinstance(frame, dict) or frame.get("@type") != root_type:
        raise ValueError("incorrect RDF root type")
    if frame.get("@context") != context:
        raise ValueError("incorrect RDF context")
    members = frame.get(collection)
    if not isinstance(members, list):
        raise ValueError("missing RDF list")
    plain_members: list[Record] = []
    for member in members:
        if not isinstance(member, dict) or member.get("@type") != member_type:
            raise ValueError("incorrect RDF list member type")
        inner = _plain({key: value for key, value in member.items() if key != "@type"})
        plain_members.append(inner)

    root: Record = _plain(
        {key: value for key, value in frame.items() if key not in {"@context", "@type", collection}}
    )
    root[collection] = plain_members
    return root


def _rdf_assessment(frame: Any, catalogue: Catalogue) -> Record:
    if not isinstance(frame, dict):
        raise ValueError("missing nested assessment")
    return {**frame, "evidence": _unframe("evidence", frame.get("evidence"), catalogue)}


def _rdf_verification(frame: Record, catalogue: Catalogue) -> Record:
    request: Record = frame["request"]
    if request.get("profile") == BASE + "transfer-request":
        request = {
            **request,
            "source": _rdf_assessment(request.get("source"), catalogue),
            "target": _rdf_assessment(request.get("target"), catalogue),
        }
    else:
        request = _rdf_assessment(request, catalogue)
    return {
        "profile": BASE + "verification-request",
        "request": request,
        "result": _unframe("result", frame["result"], catalogue),
    }


def _direct(request: Record, clockcheck: str | None) -> Record:
    evaluate = partial(assess, clockcheck=clockcheck)
    if request["profile"] == BASE + "transfer-request":
        return carry(bind(request["source"]), bind(request["target"]), evaluate)
    return evaluate(bind(request))


def evaluate_request(payload: Any, catalogue: Catalogue, clockcheck: str | None) -> Record:
    """Validate an envelope, then perform the operation it names."""
    if not isinstance(payload, dict):
        return {"status": "invalid"}
    profile = payload.get("profile")
    if profile == BASE + "rdf-verification-request":
        if not catalogue.accepts("rdf-verification-request", payload):
            return {"status": "invalid"}
        payload = _rdf_verification(payload, catalogue)
        profile = payload["profile"]
    if profile == BASE + "verification-request":
        if not catalogue.accepts("verification-request", payload):
            return {"status": "invalid"}
        result = _direct(payload["request"], clockcheck)
        equal = canonical(result) == canonical(payload["result"])
        return {"status": "verified" if equal else "mismatch"}
    if profile == BASE + "request":
        if not catalogue.accepts("request", payload):
            return {"status": "invalid"}
        if payload["operation"] == "validate":
            return {"status": "valid"}
        return _direct(payload, clockcheck)
    if profile == BASE + "transfer-request" and catalogue.accepts("transfer-request", payload):
        return _direct(payload, clockcheck)
    return {"status": "invalid"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qualref")
    commands = parser.add_subparsers(dest="operation", required=True)
    serve = commands.add_parser(
        "serve-process", help="read one JSON request and write one response"
    )
    serve.add_argument("--spec-dir", type=Path, help="local qualification specification or schemas")
    serve.add_argument("--clockcheck", help="path to the clockcheck executable")
    serve.add_argument("--input", type=Path, help="read the request from a file")
    args = parser.parse_args(argv)

    schema_dir: Path | None = args.spec_dir
    if schema_dir is not None and (schema_dir / "schema").is_dir():
        schema_dir = schema_dir / "schema"
    clockcheck = args.clockcheck or shutil.which("clockcheck")
    try:
        if args.input is None:
            data = sys.stdin.buffer.read(LIMIT + 1)
        else:
            with args.input.open("rb") as request_file:
                data = request_file.read(LIMIT + 1)
        result = evaluate_request(parse(data), Catalogue(schema_dir), clockcheck)
    except (ValueError, OSError, RecursionError):
        result = {"status": "invalid"}

    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
