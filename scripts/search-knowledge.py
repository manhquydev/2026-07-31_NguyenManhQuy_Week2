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


def terms(value: str) -> set[str]:
    return set(TOKEN.findall(value.casefold()))


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _checked_record(record: dict[str, Any], *, title: str | None = None) -> dict[str, str]:
    if not isinstance(record, dict):
        raise ValueError("corpus record is invalid")
    required = ("id", "source", "source_ref", "sha256")
    if any(not isinstance(record.get(field), str) or not record[field] for field in required):
        raise ValueError("corpus record metadata is invalid")
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
    if not isinstance(manifest.get("documents"), list) or not isinstance(manifest.get("examples"), list):
        raise ValueError("corpus manifest collections are invalid")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for document in manifest.get("documents", []):
        checked = _checked_record(document)
        if checked["id"] in seen:
            raise ValueError(f"duplicate corpus id: {checked['id']}")
        seen.add(checked["id"])
        records.append(checked)
    for example in manifest.get("examples", []):
        path = _example_path(example.get("path"))
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("id") != example.get("id"):
            raise ValueError(f"example id mismatch: {example.get('id', '[missing]')}")
        checked = _checked_record({**example, "content": payload.get("content")},
                                  title=example.get("id"))
        if checked["id"] in seen:
            raise ValueError(f"duplicate corpus id: {checked['id']}")
        seen.add(checked["id"])
        records.append(checked)
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
