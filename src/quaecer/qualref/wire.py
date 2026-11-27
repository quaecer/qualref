# SPDX-License-Identifier: Apache-2.0
"""Read the qualification wire profile and bind exact accepted inputs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from fractions import Fraction
from importlib import metadata
from pathlib import Path
from typing import Any, Never

from quaecer.spec_qualification import MAX_REQUEST_BYTES

BASE = "https://quaecer.github.io/specs/qualification/1.0/"
LIMIT = MAX_REQUEST_BYTES
_SAFE_INTEGER = 2**53 - 1

_STEMS = (
    "common",
    "evidence",
    "policy",
    "rdf-verification-request",
    "request",
    "response",
    "result",
    "transfer-request",
    "use-registry",
    "verification-request",
)
_SCHEMA_FILES = frozenset(f"{stem}.schema.json" for stem in _STEMS)
_ANNOTATIONS = {"$defs", "$id", "$schema", "contentEncoding", "format", "title"}
_KEYWORDS = _ANNOTATIONS | {
    "$ref",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "contains",
    "else",
    "enum",
    "if",
    "items",
    "maxItems",
    "maxLength",
    "maximum",
    "minItems",
    "minLength",
    "minimum",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "then",
    "type",
    "uniqueItems",
}
_TYPES: dict[str, type[object]] = {
    "array": list,
    "integer": int,
    "null": type(None),
    "object": dict,
    "string": str,
}
_TIMESTAMP = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?"
    r"(?:Z|(?!-00:00)[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON member")
    return result


def _integer(token: str) -> int:
    value = int(token)
    if abs(value) > _SAFE_INTEGER:
        raise ValueError("integer outside the interoperable range")
    return value


def _invalid_number(token: str) -> Never:
    raise ValueError(f"number outside the integer-only profile: {token[:32]}")


def _check_json(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object key is not a string")
            _check_json(key)
            _check_json(child)
    elif isinstance(value, list):
        for child in value:
            _check_json(child)
    elif isinstance(value, str):
        if not value.isascii():
            value.encode("utf-8")  # Reject unpaired escaped surrogates.
    elif type(value) is int:
        if abs(value) > _SAFE_INTEGER:
            raise ValueError("integer outside the interoperable range")
    elif value is not None and type(value) is not bool:
        raise ValueError("value outside the JSON wire profile")


def parse(raw: bytes) -> Any:
    """Decode one UTF-8 JSON input in the integer-only wire profile."""
    if len(raw) > LIMIT:
        raise ValueError("JSON input exceeds the byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_members,
            parse_int=_integer,
            parse_float=_invalid_number,
            parse_constant=_invalid_number,
        )
        _check_json(value)
    except RecursionError as exc:
        raise ValueError("JSON input is nested too deeply") from exc
    return value


def _ordered(value: Any) -> Any:
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return {key: _ordered(value[key]) for key in keys}
    if isinstance(value, list):
        return [_ordered(child) for child in value]
    return value


def canonical(value: Any) -> bytes:
    """Encode an integer-only JSON wire value according to RFC 8785."""
    try:
        _check_json(value)
        return json.dumps(_ordered(value), ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except RecursionError as exc:
        raise ValueError("JSON value is nested too deeply") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def instant(value: str) -> datetime:
    """Interpret a precise timestamp as a representable UTC instant."""
    if not _TIMESTAMP.fullmatch(value):
        raise ValueError("invalid qualification timestamp")
    try:
        return datetime.fromisoformat(value).astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValueError("timestamp is not a representable UTC instant") from exc


class Catalogue:
    """Load the fixed local wire vocabulary and compact JSON-LD contexts."""

    def __init__(self, schema_dir: Path | None = None) -> None:
        if schema_dir is None:
            try:
                distribution = metadata.distribution("quaecer-spec-qualification")
            except metadata.PackageNotFoundError as exc:
                raise ValueError("qualification specification assets are unavailable") from exc
            assets = Path(str(distribution.locate_file("quaecer/spec_qualification/_assets")))
            schema_dir = assets / "schema"
        self._schema_dir = schema_dir
        self._schemas: dict[str, dict[str, Any]] = {}

    def _document(self, filename: str) -> dict[str, Any]:
        if filename not in _SCHEMA_FILES:
            raise ValueError("schema reference leaves the qualification vocabulary")
        if filename not in self._schemas:
            schema = parse((self._schema_dir / filename).read_bytes())
            if not isinstance(schema, dict) or schema.get("$id") != BASE + filename:
                raise ValueError("unexpected qualification schema identifier")
            self._schemas[filename] = schema
        return self._schemas[filename]

    def _resolve(self, current: str, ref: str) -> tuple[str, dict[str, Any]]:
        filename, _, pointer = ref.removeprefix(BASE).partition("#")
        filename = filename or current
        schema = self._document(filename)
        if pointer:
            if not pointer.startswith("/"):
                raise ValueError("unsupported schema reference fragment")
            for part in pointer[1:].split("/"):
                schema = schema[part.replace("~1", "/").replace("~0", "~")]
        return filename, schema

    def accepts(self, name: str, data: Any) -> bool:
        filename = name.removeprefix(BASE)
        if not filename.endswith(".schema.json"):
            filename += ".schema.json"
        try:
            _check_json(data)
            return self._matches(filename, self._document(filename), data)
        except (ValueError, KeyError, RecursionError):
            return False

    def context(self, kind: str) -> dict[str, Any]:
        if kind not in {"evidence", "result"}:
            raise ValueError("unknown qualification context")
        path = self._schema_dir.parent / "context" / f"{kind}.jsonld"
        context = parse(path.read_bytes())["@context"]
        if not isinstance(context, dict):
            raise ValueError("invalid qualification context asset")
        return context

    def _matches(self, filename: str, schema: dict[str, Any], value: Any) -> bool:
        if schema.keys() - _KEYWORDS:
            raise ValueError("unsupported qualification schema vocabulary")
        if "$ref" in schema:
            referenced_file, referenced_schema = self._resolve(filename, schema["$ref"])
            if not self._matches(referenced_file, referenced_schema, value):
                return False

        if "type" in schema and type(value) is not _TYPES[schema["type"]]:
            return False
        if "const" in schema and not _same_value(value, schema["const"]):
            return False
        if "enum" in schema and not any(_same_value(value, item) for item in schema["enum"]):
            return False

        if isinstance(value, dict) and not self._object_matches(filename, schema, value):
            return False
        if isinstance(value, list) and not self._array_matches(filename, schema, value):
            return False
        if isinstance(value, str):
            if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
                return False
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                return False
        if type(value) is int and not schema.get("minimum", value) <= value <= schema.get(
            "maximum", value
        ):
            return False

        if "allOf" in schema and not all(
            self._matches(filename, branch, value) for branch in schema["allOf"]
        ):
            return False
        if "anyOf" in schema and not any(
            self._matches(filename, branch, value) for branch in schema["anyOf"]
        ):
            return False
        if (
            "oneOf" in schema
            and sum(self._matches(filename, branch, value) for branch in schema["oneOf"]) != 1
        ):
            return False
        if "if" in schema:
            branch_name = "then" if self._matches(filename, schema["if"], value) else "else"
            return self._matches(filename, schema.get(branch_name, {}), value)
        return True

    def _object_matches(self, filename: str, schema: dict[str, Any], value: dict[str, Any]) -> bool:
        properties = schema.get("properties", {})
        if set(schema.get("required", ())) - value.keys():
            return False
        if schema.get("additionalProperties") is False and value.keys() - properties.keys():
            return False
        return all(
            self._matches(filename, properties[key], value[key])
            for key in value.keys() & properties.keys()
        )

    def _array_matches(self, filename: str, schema: dict[str, Any], value: list[Any]) -> bool:
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            return False
        if schema.get("uniqueItems") and len({canonical(item) for item in value}) != len(value):
            return False
        if "items" in schema and not all(
            self._matches(filename, schema["items"], item) for item in value
        ):
            return False
        return "contains" not in schema or any(
            self._matches(filename, schema["contains"], item) for item in value
        )


def _same_value(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, (dict, list)):
        return canonical(left) == canonical(right)
    return bool(left == right)


@dataclass(frozen=True, slots=True)
class View:
    policy: dict[str, Any]
    registry: dict[str, Any]
    reports: dict[str, dict[str, Any]]
    selected: dict[str, dict[str, Any]]
    pins: dict[str, dict[str, str]]
    bodies: dict[bytes, bytes]
    view_digest: str
    policy_digest: str


def _by_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index = {item["id"]: item for item in items}
    if len(index) != len(items):
        raise ValueError("duplicate identifier in a wire map")
    return index


def _revision_pins(value: Any) -> Iterator[dict[str, str]]:
    if isinstance(value, dict):
        if value.keys() == {"id", "digest"}:
            yield value
        else:
            for child in value.values():
                yield from _revision_pins(child)
    elif isinstance(value, list):
        for child in value:
            yield from _revision_pins(child)


def _registry_uses(registry: dict[str, Any]) -> set[str]:
    uses: set[str] = set(registry["uses"])
    successors: dict[str, list[str]] = {use: [] for use in uses}
    incoming = dict.fromkeys(uses, 0)
    for edge in registry["edges"]:
        target, source = edge["target"], edge["source"]
        if target not in uses or source not in uses or target == source:
            raise ValueError("registry edge must join different declared uses")
        successors[target].append(source)
        incoming[source] += 1
    ready = deque(use for use, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        current = ready.popleft()
        visited += 1
        for successor in successors[current]:
            incoming[successor] -= 1
            if incoming[successor] == 0:
                ready.append(successor)
    if visited != len(uses):
        raise ValueError("registry contains a use cycle")
    return uses


def _interval(interval: dict[str, str]) -> tuple[datetime, datetime]:
    start = instant(interval["start"])
    end = instant(interval["end"])
    if start >= end:
        raise ValueError("empty or reversed half-open interval")
    return start, end


def _interpret_policy(policy: dict[str, Any], uses: set[str]) -> None:
    use_kind = policy["use"]["kind"]
    if use_kind not in uses:
        raise ValueError("policy use is absent from registry")
    _interval(policy["window"])
    if instant(policy["history_scope"]["start"]) >= instant(policy["lock_at"]):
        raise ValueError("empty or reversed history scope")
    applicable = []
    for rule in _by_id(policy["rules"]).values():
        if not uses.issuperset(rule["uses"]):
            raise ValueError("rule applicability names an undeclared use")
        if rule["operator"] == "control" and Fraction(rule["tolerance"]) < 0:
            raise ValueError("negative control tolerance")
        if use_kind in rule["uses"]:
            applicable.append(rule["operator"])
    if not applicable:
        raise ValueError("no rule applies to the declared use")
    if applicable.count("dependence") > 1:
        raise ValueError("multiple applicable dependence comparisons")
    if "no_prelock_exposure" in applicable and not policy["forbidden"]:
        raise ValueError("absence scope has no forbidden resource")


def _interpret_report(report: dict[str, Any]) -> None:
    if report.get("at") is not None:
        instant(report["at"])
    if "interval" in report:
        _interval(report["interval"])
    if report["kind"] == "completeness":
        for segment in report["segments"]:
            _interval(segment["interval"])
        for unit in report["segments"] or [report]:
            for entry in unit["entries"]:
                if entry.get("at") is not None:
                    instant(entry["at"])


def _commitments(reports: dict[str, dict[str, Any]], accepted: dict[str, dict[str, Any]]) -> None:
    segment_ids: set[str] = set()
    unit_count = 0
    entry_count = 0
    for report in accepted.values():
        if report["kind"] != "completeness":
            continue
        units = report["segments"] or [report]
        if report["segments"]:
            _partition(report, units)
            for segment in units:
                segment_id = segment["id"]
                if segment_id in reports or segment_id in segment_ids:
                    raise ValueError("segment identifier is reused")
                segment_ids.add(segment_id)
        for unit in units:
            entries = unit["entries"]
            if len({entry["event_id"] for entry in entries}) != len(entries):
                raise ValueError("event identifier is reused in an inventory")
            if digest(entries) != unit["inventory_digest"]:
                raise ValueError("inventory digest does not match its entries")
            unit_count += 1
            entry_count += len(entries)
            if unit_count > 100 or entry_count > 500:
                raise ValueError("accepted inventories exceed the unit or entry limit")


def _partition(report: dict[str, Any], units: list[dict[str, Any]]) -> None:
    start, end = _interval(report["interval"])
    intervals = sorted(_interval(unit["interval"]) for unit in units)
    for lower, upper in intervals:
        if lower != start:
            raise ValueError("segments do not form a partition of the parent scope")
        start = upper
    if start != end:
        raise ValueError("segments do not cover the parent scope")


def _bodies(entries: list[dict[str, Any]]) -> dict[bytes, bytes]:
    bodies: dict[bytes, bytes] = {}
    for entry in entries:
        key = canonical(entry["artifact"])
        if key in bodies:
            raise ValueError("artifact body is supplied more than once")
        encoded = entry["bytes_base64"]
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError("body is not valid Base64") from exc
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError("body is not canonical padded Base64")
        bodies[key] = decoded
    return bodies


def bind(request: dict[str, Any]) -> View:
    """Bind a structurally valid assessment request or raise an operational refusal."""
    policy = request["policy"]
    registry = request["use_registry"]
    evidence = request["evidence"]
    caller = request["caller"]
    policy_digest = digest(policy)
    registry_digest = digest(registry)

    for key in ("subject", "implementation"):
        if policy[key] != evidence[key] or policy[key] != caller[key]:
            raise ValueError(f"{key} pin differs across the request")
    if (
        policy["use"]["id"] != evidence["use"]
        or policy["use"]["id"] != caller["use"]
        or policy["use"]["claim"] != evidence["claim"]
    ):
        raise ValueError("use or claim differs across the request")
    if policy_digest != evidence["policy_digest"] or policy_digest != caller["policy_digest"]:
        raise ValueError("policy digest does not bind")
    if (
        registry_digest != policy["use_registry_digest"]
        or registry_digest != caller["use_registry_digest"]
    ):
        raise ValueError("registry digest does not bind")

    _interpret_policy(policy, _registry_uses(registry))
    references = _by_id(evidence["references"])
    reports = _by_id(evidence["reports"])
    if references.keys() & reports.keys():
        raise ValueError("report identifier is also an external reference")
    for value in (policy, evidence, caller["bodies"]):
        for pin in _revision_pins(value):
            if references.get(pin["id"]) != pin:
                raise ValueError("revision pin does not resolve")
    for raw_report in reports.values():
        _interpret_report(raw_report)

    pins: dict[str, dict[str, str]] = _by_id(caller["report_pins"])
    selected = {}
    for report_id, pin in pins.items():
        report = reports.get(report_id)
        if report is None or digest(report) != pin["digest"]:
            raise ValueError("selected report is missing or changed")
        if (
            report["subject"] != policy["subject"]
            or report["implementation"] != policy["implementation"]
        ):
            raise ValueError("selected report has a different scope")
        selected[report_id] = report
    _commitments(reports, selected)
    bodies = _bodies(caller["bodies"])

    binding = {
        "claim": evidence["claim"],
        "subject": policy["subject"],
        "implementation": policy["implementation"],
        "use_registry_digest": registry_digest,
        "references": [references[key] for key in sorted(references)],
        "reports": [pins[key] for key in sorted(pins)],
        "bodies": sorted(caller["bodies"], key=lambda body: body["artifact"]["id"]),
    }
    return View(policy, registry, reports, selected, pins, bodies, digest(binding), policy_digest)


def basis(view: View, report_ids: Iterable[str]) -> list[dict[str, str]]:
    """Collect the accepted matching reports and their explicit supporting pins."""
    pins: dict[str, dict[str, str]] = {}
    for report_id in set(report_ids) & view.selected.keys():
        pins[report_id] = view.pins[report_id]
        pins.update((pin["id"], pin) for pin in view.selected[report_id]["basis"])
    return [pins[key] for key in sorted(pins)]


def reason(
    code: str,
    *,
    criterion: str | None = None,
    reports: Iterable[str] = (),
    related: Iterable[str] = (),
    channel: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "report_ids": sorted(set(reports)),
        "related_ids": sorted(set(related)),
        "channel": channel,
        "criterion": criterion,
    }
