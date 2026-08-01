#!/usr/bin/env python3
"""Self-contained Week-2 delivery acceptance and hardening tests."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_INPUT = os.environ.get("PYTHON", sys.executable)
PYTHON_FOUND = shutil.which(PYTHON_INPUT)
# Keep a virtualenv executable adjacent to its ``pyvenv.cfg``.  ``resolve()``
# dereferences `.venv/bin/python` to the base interpreter and silently escapes
# the hash-locked environment; ``abspath()`` makes relative/PATH results stable
# without following that symlink.
PYTHON = os.path.abspath(PYTHON_FOUND) if PYTHON_FOUND else PYTHON_INPUT
MANIFEST = ROOT / "rag" / "charter-corpus-manifest.json"
SEARCH = ROOT / "scripts" / "search-knowledge.py"
RUNNER = ROOT / "scripts" / "run-week2-checks.sh"
EXPECTED_OWASP_COVERAGE = [
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
]
EXPECTED_TOOL_COVERAGE = ["nuclei", "trivy", "semgrep"]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def delivery_source_hashes(root: Path) -> dict[Path, str]:
    return {
        path.relative_to(root): sha256_file(path)
        for path in root.rglob("*")
        if (
            path.is_file()
            and ".git" not in path.parts
            and ".venv" not in path.parts
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        )
    }


def run(*args: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONPATH"] = str(cwd)
    if env:
        merged.update(env)
    return subprocess.run(args, cwd=cwd, env=merged, text=True, capture_output=True)


def search_at(root: Path, query: str, k: int) -> subprocess.CompletedProcess[str]:
    return run(PYTHON, str(root / "scripts/search-knowledge.py"), query, "-k", str(k), cwd=root)


def search(query: str, k: int) -> subprocess.CompletedProcess[str]:
    return search_at(ROOT, query, k)


def virtualenv_root(executable: str) -> Path | None:
    executable_path = Path(executable)
    if not executable_path.is_absolute():
        return None
    for parent in executable_path.parents:
        if (parent / "pyvenv.cfg").is_file():
            return parent
    return None


class Week2DeliveryTest(unittest.TestCase):
    maxDiff = None

    def test_selected_virtualenv_interpreter_remains_in_its_virtualenv(self) -> None:
        expected_root = virtualenv_root(PYTHON)
        if expected_root is None:
            self.skipTest("the selected interpreter is not a virtualenv executable")
        result = run(PYTHON, "-c", "import sys; print(sys.prefix)")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(expected_root.resolve(), Path(result.stdout.strip()).resolve())

    def test_corpus_contract(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        documents = manifest["documents"]
        examples = manifest["examples"]
        all_records = [*documents, *examples]
        ids = [record["id"] for record in all_records]
        self.assertEqual(25, len(all_records))
        self.assertEqual(25, len(set(ids)))
        self.assertEqual(12, len(examples))
        self.assertEqual(
            EXPECTED_TOOL_COVERAGE,
            manifest["required_coverage"]["scanner_tool_docs"],
        )
        self.assertEqual(EXPECTED_OWASP_COVERAGE, manifest["required_coverage"]["owasp_top_10"])
        self.assertEqual("sentinel-charter-corpus/v1", manifest["schema_version"])
        self.assertEqual("sentinel-charter-v1", manifest["corpus_version"])

        semgrep = next(record for record in documents if record["id"] == "tool-semgrep")
        self.assertEqual({"scanner_tool_docs": "semgrep"}, semgrep["coverage"])
        expected_coverage_ids = {
            **{value: f"owasp-a{index:02d}" for index, value in enumerate(EXPECTED_OWASP_COVERAGE, 1)},
            **{value: f"tool-{value}" for value in EXPECTED_TOOL_COVERAGE},
        }

        for document in documents:
            for field in (
                "source",
                "source_ref",
                "license",
                "source_license",
                "content_origin",
                "version",
                "content",
            ):
                self.assertIsInstance(document[field], str)
                self.assertTrue(document[field])
            self.assertTrue(document["source_ref"].startswith("https://"))
            self.assertEqual("sentinel-charter-v1", document["version"])
            self.assertEqual(document["sha256"], sha256_bytes(document["content"].encode()))
            self.assertEqual(1, len(document["coverage"]))
            coverage_value = next(iter(document["coverage"].values()))
            self.assertEqual(expected_coverage_ids[coverage_value], document["id"])
        for example in examples:
            for field in (
                "source",
                "source_ref",
                "license",
                "source_license",
                "content_origin",
                "version",
            ):
                self.assertIsInstance(example[field], str)
                self.assertTrue(example[field])
            self.assertTrue(example["source_ref"].startswith("https://"))
            self.assertEqual("sentinel-charter-v1", example["version"])
            relative = Path(example["path"])
            self.assertFalse(relative.is_absolute())
            self.assertNotIn("..", relative.parts)
            path = ROOT / "rag" / relative
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(example["id"], payload["id"])
            self.assertEqual(example["sha256"], sha256_bytes(payload["content"].encode()))

    def test_search_oracles_content_digest_and_determinism(self) -> None:
        cases = {
            ("SQL Injection", 3): [
                "owasp-a03",
                "sqli-error-handling",
                "sqli-input-allowlist",
            ],
            ("XSS", 3): [
                "xss-contextual-encoding",
                "xss-dom-sink",
                "xss-output-encoding",
            ],
            ("Server-Side Request Forgery", 1): ["owasp-a10"],
        }
        for (query, k), expected_ids in cases.items():
            with self.subTest(query=query):
                first = search(query, k)
                second = search(query, k)
                self.assertEqual(0, first.returncode, first.stderr)
                self.assertEqual(first.stdout, second.stdout)
                payload = json.loads(first.stdout)
                self.assertEqual(expected_ids, [row["id"] for row in payload["results"]])
                for row in payload["results"]:
                    self.assertEqual(row["sha256"], sha256_bytes(row["content"].encode()))
                    self.assertFalse(row["content"].lstrip().startswith("{"))

    def test_unrelated_query_contract(self) -> None:
        result = search("quantum teleportation", 3)
        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("no relevant knowledge found\n", result.stderr)

    def test_search_rejects_invalid_source_ref_without_output(self) -> None:
        invalid_refs = (
            "https:///path",
            "https://user:pass@host/path",
            " https://host/path",
            "https://host\n/path",
        )
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "delivery"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
            manifest_path = copied / "rag/charter-corpus-manifest.json"
            for source_ref in invalid_refs:
                with self.subTest(source_ref=source_ref):
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["documents"][0]["source_ref"] = source_ref
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    result = search_at(copied, "XSS", 1)
                    self.assertEqual(1, result.returncode)
                    self.assertEqual("", result.stdout)
                    self.assertEqual(
                        "corpus validation failed: corpus source_ref is invalid: owasp-a01\n",
                        result.stderr,
                    )

    def test_aggregate_contract_and_reproducibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "aggregate.jsonl"
            generated_manifest = Path(directory) / "aggregate.manifest.json"
            result = run(
                PYTHON,
                "-m",
                "agent.normalize_week1_artifacts",
                "--submission-dir",
                str(ROOT),
                "--output",
                str(output),
                "--manifest-output",
                str(generated_manifest),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual((ROOT / "artifacts/week1.aggregate.jsonl").read_bytes(), output.read_bytes())
            self.assertEqual(
                (ROOT / "artifacts/week1.aggregate.manifest.json").read_bytes(),
                generated_manifest.read_bytes(),
            )
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(generated_manifest.stat().st_mode))

            records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(36, len(records))
            self.assertEqual(36, len({row["finding_id"] for row in records}))
            source_ids = [source for row in records for source in row["source_ids"]]
            self.assertEqual(36, len(source_ids))
            self.assertEqual(36, len(set(source_ids)))
            self.assertEqual(
                {"nuclei": 21, "trivy": 4, "semgrep": 11},
                {
                    tool: sum(row["tool"] == tool for row in records)
                    for tool in ("nuclei", "trivy", "semgrep")
                },
            )
            self.assertTrue(all(row["schema_version"] == "week1-submission/v1" for row in records))
            self.assertTrue(all(row["provenance_kind"] == "week1-submission" for row in records))

            aggregate_manifest = json.loads(generated_manifest.read_text(encoding="utf-8"))
            for item in aggregate_manifest["inputs"]:
                self.assertEqual(item["sha256"], sha256_file(ROOT / item["filename"]))

    def test_output_existing_is_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "aggregate.jsonl"
            manifest = Path(directory) / "aggregate.manifest.json"
            output.write_text("KEEP\n", encoding="utf-8")
            result = run(
                PYTHON,
                "-m",
                "agent.normalize_week1_artifacts",
                "--submission-dir",
                str(ROOT),
                "--output",
                str(output),
                "--manifest-output",
                str(manifest),
            )
            self.assertNotEqual(0, result.returncode)
            self.assertEqual("KEEP\n", output.read_text(encoding="utf-8"))
            self.assertFalse(manifest.exists())

    def test_malformed_symlink_and_fifo_inputs_publish_nothing(self) -> None:
        for mode in ("malformed", "symlink", "fifo"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                copied = Path(directory) / "delivery"
                shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
                nuclei = copied / "scanners/out/nuclei.san.jsonl"
                if mode == "malformed":
                    nuclei.write_text("{not-json}\n", encoding="utf-8")
                else:
                    target = copied / "nuclei-target.jsonl"
                    target.write_bytes(nuclei.read_bytes())
                    nuclei.unlink()
                    if mode == "symlink":
                        nuclei.symlink_to(target)
                    else:
                        os.mkfifo(nuclei)
                output = copied / "tmp.aggregate.jsonl"
                generated_manifest = copied / "tmp.manifest.json"
                result = run(
                    PYTHON,
                    "-m",
                    "agent.normalize_week1_artifacts",
                    "--submission-dir",
                    str(copied),
                    "--output",
                    str(output),
                    "--manifest-output",
                    str(generated_manifest),
                    cwd=copied,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(output.exists())
                self.assertFalse(generated_manifest.exists())

    def test_free_text_locator_is_redacted_and_unsafe_file_location_is_opaque(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "delivery"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
            semgrep_path = copied / "scanners/out/semgrep.san.json"
            semgrep = json.loads(semgrep_path.read_text(encoding="utf-8"))
            semgrep["results"][0]["check_id"] = (
                "safe-rule https://example.invalid/rule?token=secret"
            )
            semgrep["results"][0]["path"] = "localhost/scan"
            semgrep_path.write_text(json.dumps(semgrep), encoding="utf-8")
            output = copied / "tmp.aggregate.jsonl"
            generated_manifest = copied / "tmp.manifest.json"
            result = run(
                PYTHON,
                "-m",
                "agent.normalize_week1_artifacts",
                "--submission-dir",
                str(copied),
                "--output",
                str(output),
                "--manifest-output",
                str(generated_manifest),
                cwd=copied,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("example.invalid", text)
            self.assertNotIn("token=secret", text)
            self.assertIn("[redacted:locator]", text)
            rows = [json.loads(line) for line in text.splitlines()]
            self.assertTrue(any(row["tool"] == "semgrep" and row["location"].startswith("semgrep:")
                                for row in rows))

    @unittest.skipIf(
        os.environ.get("WEEK2_SKIP_SELF_MUTATION") == "1",
        "avoid recursive mutation-runner tests",
    )
    def test_runner_detects_committed_artifact_and_corpus_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory).resolve() / "delivery"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
            control = run(
                "bash",
                str(copied / "scripts/run-week2-checks.sh"),
                cwd=copied,
                env={"PYTHON": PYTHON, "WEEK2_SKIP_SELF_MUTATION": "1"},
            )
            self.assertEqual(0, control.returncode, control.stderr)

        source_hashes = delivery_source_hashes(ROOT)
        mutations = (
            "aggregate",
            "input",
            "inline-digest",
            "example-content",
            "schema-version",
            "coverage",
            "coverage-spoof",
            "duplicate-id",
            "missing-provenance",
            "source-ref-no-host",
            "source-ref-userinfo",
            "source-ref-leading-whitespace",
            "source-ref-newline",
            "absolute",
            "traversal",
            "missing-example",
            "malformed-example-record",
            "example-id",
            "example-symlink",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                copied = Path(directory).resolve() / "delivery"
                shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
                self.assertTrue(copied.is_relative_to(Path(directory).resolve()))
                manifest_path = copied / "rag/charter-corpus-manifest.json"
                if mutation == "aggregate":
                    (copied / "artifacts/week1.aggregate.jsonl").write_bytes(b"{}\n")
                elif mutation == "input":
                    with (copied / "scanners/out/nuclei.san.jsonl").open("ab") as handle:
                        handle.write(b"\n")
                else:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if mutation == "inline-digest":
                        manifest["documents"][0]["content"] += " tampered"
                    elif mutation == "example-content":
                        example_path = copied / "rag" / manifest["examples"][0]["path"]
                        payload = json.loads(example_path.read_text(encoding="utf-8"))
                        payload["content"] += " tampered"
                        example_path.write_text(json.dumps(payload), encoding="utf-8")
                    elif mutation == "schema-version":
                        manifest["schema_version"] = "sentinel-charter-corpus/v999"
                    elif mutation == "coverage":
                        manifest["required_coverage"]["scanner_tool_docs"].remove("semgrep")
                    elif mutation == "coverage-spoof":
                        manifest["required_coverage"]["owasp_top_10"][0] = "A99:2099-Bogus"
                        manifest["documents"][0]["id"] = "fake-a01"
                        manifest["documents"][0]["coverage"] = {"owasp_top_10": "A99:2099-Bogus"}
                    elif mutation == "duplicate-id":
                        manifest["documents"][1]["id"] = manifest["documents"][0]["id"]
                    elif mutation == "missing-provenance":
                        manifest["documents"][0].pop("source_license")
                    elif mutation == "source-ref-no-host":
                        manifest["documents"][0]["source_ref"] = "https:///path"
                    elif mutation == "source-ref-userinfo":
                        manifest["documents"][0]["source_ref"] = "https://user:pass@host/path"
                    elif mutation == "source-ref-leading-whitespace":
                        manifest["documents"][0]["source_ref"] = " https://host/path"
                    elif mutation == "source-ref-newline":
                        manifest["documents"][0]["source_ref"] = "https://host\n/path"
                    elif mutation == "absolute":
                        manifest["examples"][0]["path"] = "/tmp/outside-corpus.json"
                    elif mutation == "traversal":
                        manifest["examples"][0]["path"] = "../../README.md"
                    elif mutation == "missing-example":
                        example_path = copied / "rag" / manifest["examples"][0]["path"]
                        example_path.unlink()
                    elif mutation == "malformed-example-record":
                        manifest["examples"][0] = "invalid"
                    elif mutation == "example-id":
                        example_path = copied / "rag" / manifest["examples"][0]["path"]
                        payload = json.loads(example_path.read_text(encoding="utf-8"))
                        payload["id"] = "different-id"
                        example_path.write_text(json.dumps(payload), encoding="utf-8")
                    elif mutation == "example-symlink":
                        example_path = copied / "rag" / manifest["examples"][0]["path"]
                        target = copied / "rag" / manifest["examples"][1]["path"]
                        example_path.unlink()
                        example_path.symlink_to(target)
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                result = run(
                    "bash",
                    str(copied / "scripts/run-week2-checks.sh"),
                    cwd=copied,
                    env={"PYTHON": PYTHON, "WEEK2_SKIP_SELF_MUTATION": "1"},
                )
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertNotIn("No such file or directory: '.venv/bin/python'", result.stderr)

        for relative, digest in source_hashes.items():
            self.assertEqual(digest, sha256_file(ROOT / relative), str(relative))


if __name__ == "__main__":
    unittest.main(verbosity=2)
