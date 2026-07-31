#!/usr/bin/env python3
"""Offline keyword search over the submitted Week-2 knowledge corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rag" / "charter-corpus-manifest.json"
EXAMPLES_ROOT = ROOT / "rag" / "charter-examples"
TOKEN = re.compile(r"[a-z0-9]+")
SCHEMA_VERSION = "sentinel-charter-corpus/v1"
CORPUS_VERSION = "sentinel-charter-v1"
EXPECTED_OWASP_COVERAGE = (
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery (SSRF)",
)
EXPECTED_TOOL_COVERAGE = ("nuclei", "trivy", "semgrep")
EXPECTED_COVERAGE_IDS = {
    **{value: f"owasp-a{index:02d}" for index, value in enumerate(EXPECTED_OWASP_COVERAGE, 1)},
    **{value: f"tool-{value}" for value in EXPECTED_TOOL_COVERAGE},
}


def terms(value: str) -> set[str]:
    return set(TOKEN.findall(value.casefold()))


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _checked_record(record: dict[str, Any], *, title: str | None = None) -> dict[str, str]:
    if not isinstance(record, dict):
        raise ValueError("corpus record is invalid")
    required = (
        "id",
        "source",
        "source_ref",
        "license",
        "source_license",
        "version",
        "content_origin",
        "sha256",
    )
    if any(not isinstance(record.get(field), str) or not record[field] for field in required):
        raise ValueError("corpus record metadata is invalid")
    if not record["source_ref"].startswith("https://"):
        raise ValueError(f"corpus source_ref is invalid: {record['id']}")
    if record["version"] != CORPUS_VERSION:
        raise ValueError(f"corpus version is invalid: {record['id']}")
    content = record.get("content")
    if not isinstance(content, str) or not content:
        raise ValueError(f"corpus content is invalid: {record['id']}")
    if not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) or _digest(content) != record["sha256"]:
        raise ValueError(f"corpus digest mismatch: {record['id']}")
    record_title = title if title is not None else record.get("title")
    if not isinstance(record_title, str) or not record_title:
        raise ValueError(f"corpus title is invalid: {record['id']}")
    return {
        "id": record["id"],
        "title": record_title,
        "content": content,
        "source": record["source"],
        "source_ref": record["source_ref"],
        "sha256": record["sha256"],
    }


def _example_path(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("example path is invalid")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("charter-examples",):
        raise ValueError("example path escapes the corpus")
    candidate = ROOT / "rag" / relative
    current = ROOT / "rag"
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("example path may not contain a symlink")
    try:
        resolved_root = EXAMPLES_ROOT.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError("example path is unavailable") from error
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError("example path escapes the corpus") from error
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError("example path is not a regular file")
    return resolved


def documents() -> list[dict[str, str]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("corpus manifest is invalid")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("corpus schema_version is invalid")
    if manifest.get("corpus_version") != CORPUS_VERSION:
        raise ValueError("corpus_version is invalid")
    coverage = manifest.get("required_coverage")
    if not isinstance(coverage, dict):
        raise ValueError("required corpus coverage is invalid")
    if coverage.get("owasp_top_10") != list(EXPECTED_OWASP_COVERAGE):
        raise ValueError("required OWASP coverage is invalid")
    if coverage.get("scanner_tool_docs") != list(EXPECTED_TOOL_COVERAGE):
        raise ValueError("required scanner coverage is invalid")
    if not isinstance(manifest.get("documents"), list) or not isinstance(manifest.get("examples"), list):
        raise ValueError("corpus manifest collections are invalid")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    found_coverage: set[str] = set()
    for document in manifest.get("documents", []):
        checked = _checked_record(document)
        if checked["id"] in seen:
            raise ValueError(f"duplicate corpus id: {checked['id']}")
        coverage_item = document.get("coverage")
        if not isinstance(coverage_item, dict) or len(coverage_item) != 1:
            raise ValueError(f"corpus coverage is invalid: {checked['id']}")
        category, value = next(iter(coverage_item.items()))
        if category == "owasp_top_10":
            allowed = EXPECTED_OWASP_COVERAGE
        elif category == "scanner_tool_docs":
            allowed = EXPECTED_TOOL_COVERAGE
        else:
            raise ValueError(f"corpus coverage category is invalid: {checked['id']}")
        if value not in allowed or EXPECTED_COVERAGE_IDS[value] != checked["id"]:
            raise ValueError(f"corpus coverage mapping is invalid: {checked['id']}")
        if value in found_coverage:
            raise ValueError(f"duplicate corpus coverage: {value}")
        found_coverage.add(value)
        seen.add(checked["id"])
        records.append(checked)
    if found_coverage != set(EXPECTED_COVERAGE_IDS):
        raise ValueError("corpus coverage is incomplete")
    examples = manifest.get("examples", [])
    if not 10 <= len(examples) <= 20:
        raise ValueError("corpus examples must contain 10-20 entries")
    declared_paths: set[Path] = set()
    for example in examples:
        if not isinstance(example, dict):
            raise ValueError("corpus example record is invalid")
        path = _example_path(example.get("path"))
        if path in declared_paths:
            raise ValueError(f"duplicate corpus example path: {example.get('path')}")
        declared_paths.add(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("id") != example.get("id"):
            raise ValueError(f"example id mismatch: {example.get('id', '[missing]')}")
        checked = _checked_record({**example, "content": payload.get("content")},
                                  title=example.get("id"))
        if checked["id"] in seen:
            raise ValueError(f"duplicate corpus id: {checked['id']}")
        seen.add(checked["id"])
        records.append(checked)
    actual_paths = {path.resolve() for path in EXAMPLES_ROOT.rglob("*.json")}
    if actual_paths != declared_paths:
        raise ValueError("corpus examples contain missing or unmanifested files")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Search the Week-2 OWASP/tool/example corpus.")
    parser.add_argument("query")
    parser.add_argument("-k", type=int, default=3)
    args = parser.parse_args()
    if not args.query.strip() or args.k < 1:
        raise SystemExit("query must be non-empty and k must be positive")
    query_terms = terms(args.query)
    query_phrase = " ".join(TOKEN.findall(args.query.casefold()))
    ranked = []
    try:
        corpus = documents()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"corpus validation failed: {error}") from error
    for record in corpus:
        body = f"{record['title']} {record['content']}".casefold()
        body_terms = terms(body)
        if query_terms and query_terms.issubset(body_terms):
            normalized_body = " ".join(TOKEN.findall(body))
            score = len(query_terms) + (100 if query_phrase in normalized_body else 0)
            ranked.append((score, record["id"], {
                "id": record["id"],
                "content": record["content"],
                "source": record["source"],
                "source_ref": record["source_ref"],
                "sha256": record["sha256"],
                "score": score,
            }))
    results = [record for _, _, record in sorted(ranked, key=lambda item: (-item[0], item[1]))[:args.k]]
    if not results:
        raise SystemExit("no relevant knowledge found")
    print(json.dumps({"query": args.query, "results": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
