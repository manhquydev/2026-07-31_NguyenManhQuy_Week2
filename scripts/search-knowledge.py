#!/usr/bin/env python3
"""Offline keyword search over the submitted Week-2 knowledge corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rag" / "charter-corpus-manifest.json"
TOKEN = re.compile(r"[a-z0-9]+")


def terms(value: str) -> set[str]:
    return set(TOKEN.findall(value.casefold()))


def documents() -> list[dict[str, str]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    records = list(manifest["documents"])
    for example in manifest["examples"]:
        content = (ROOT / "rag" / example["path"]).read_text(encoding="utf-8")
        records.append({**example, "title": example["id"], "content": content})
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Search the Week-2 OWASP/tool/example corpus.")
    parser.add_argument("query")
    parser.add_argument("-k", type=int, default=3)
    args = parser.parse_args()
    if not args.query.strip() or args.k < 1:
        raise SystemExit("query must be non-empty and k must be positive")
    query_terms = terms(args.query)
    ranked = []
    for record in documents():
        body = f"{record['title']} {record['content']}".casefold()
        score = sum(term in body for term in query_terms)
        if score:
            content = record["content"][:600]
            ranked.append((score, record["id"], {
                "id": record["id"],
                "content": content,
                "source": record["source"],
                "source_ref": record["source_ref"],
                "sha256": hashlib.sha256(record["content"].encode("utf-8")).hexdigest(),
                "score": score,
            }))
    results = [record for _, _, record in sorted(ranked, key=lambda item: (-item[0], item[1]))[:args.k]]
    if not results:
        raise SystemExit("no relevant knowledge found")
    print(json.dumps({"query": args.query, "results": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
