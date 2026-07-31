"""Import the submitted, sanitized Week-1 scanner artifacts into a safe aggregate.

This module is intentionally separate from the Charter normalizers.  It accepts
only the three canonical files in a Week-1 *submission*, preserves every
admitted scanner datum as a distinct record, and must not be used by Charter
controller, recon, reporting, or proposal paths.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import pii


_FORBID = ConfigDict(extra="forbid")
_INPUT_LIMIT_BYTES = 1024 * 1024
_MAX_RECORDS = 5000
_MAX_DEPTH = 32
_MAX_STRING_CHARS = 16 * 1024
_REDACTION_TOKEN = re.compile(r"\[redacted:[^\]]+\]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# This is deliberately equivalent to ``trace.redact_persisted`` but local to
# this offline importer.  Importing ``agent.trace`` also imports the optional
# OpenTelemetry exporter, which must not become an availability dependency for
# a pure submitted-artifact validation command.
_SECRET_PATTERNS = re.compile(
    r"(?s:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)"
    r"|\bsk-[A-Za-z0-9_-]{10,}"
    r"|\bghp_[A-Za-z0-9]{20,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bAKIA[0-9A-Z]{16}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\b(?:token|secret|password|passwd|api[_-]?key|client[_-]secret|access[_-]token"
    r"|refresh[_-]token|private[_-]key|authorization|cookie)[\"']?\s*[:=]\s*[^\r\n]+",
    re.IGNORECASE,
)
_TARGET_RAW_PATTERNS = re.compile(
    r"<script|javascript:|UNION\s+SELECT|SequelizeDatabaseError|SQLITE_ERROR"
    r"|Traceback \(most recent call last\)|\bat Object\.<anonymous>|ORA-\d{5}"
    r"|org\.hibernate|com\.mysql|\.\./\.\./|\{\{.*?\}\}|\$\{.*?\}",
    re.IGNORECASE,
)
_SCANNER_INSTRUCTION_PATTERNS = re.compile(
    r"\bignore[-\s]+(?:prior|previous)[-\s]+(?:objective|instruction(?:s)?)\b",
    re.IGNORECASE,
)
# The aggregate is evidence for Week 2, not a target inventory.  A scanner can
# place arbitrary target-controlled strings into a title, rule identifier, or
# matcher name, so locators must be removed from every retained free-text
# field, not only from the dedicated ``location`` field.
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"`]+", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?(?![\w.])")
_HOSTNAME = re.compile(r"(?<![\w.-])(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?::\d{1,5})?(?![\w.-])", re.IGNORECASE)
_ABSOLUTE_PATH = re.compile(r"(?<![\w.-])/(?:[^\s<>'\"`\\]+)")

_CANONICAL_INPUTS: tuple[tuple[str, str, str], ...] = (
    ("nuclei", "scanners/out/nuclei.san.jsonl", "nuclei.san.jsonl"),
    ("trivy", "scanners/out/trivy.san.json", "trivy.san.json"),
    ("semgrep", "scanners/out/semgrep.san.json", "semgrep.san.json"),
)
_SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Info",
}
_SEMGREP_SEVERITIES = {"ERROR": "High", "WARNING": "Medium", "INFO": "Info"}
_TRIVY_ROOT_FIELDS = {"SchemaVersion", "ArtifactName", "ArtifactType", "Results"}
_TRIVY_RESULT_FIELDS = {"Target", "Class", "Type", "Vulnerabilities", "Secrets", "Misconfigurations"}
_TRIVY_ISSUE_FIELDS = {
    "Vulnerabilities": {"VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Title"},
    "Secrets": {"RuleID", "Category", "Severity", "Title", "StartLine", "EndLine"},
    "Misconfigurations": {"ID", "AVDID", "Title", "Description", "Severity", "Resolution", "Message"},
}
_TRIVY_REQUIRED_FIELDS = {
    "Vulnerabilities": {"VulnerabilityID", "PkgName", "Severity", "Title"},
    "Secrets": {"RuleID", "Severity", "Title"},
    "Misconfigurations": {"ID", "Severity", "Title"},
}


class Week1ImportFailure(BaseModel):
    """A typed refusal; failures never carry partially admitted records."""

    model_config = _FORBID
    schema_version: Literal["week1-submission/v1"] = "week1-submission/v1"
    code: Literal[
        "empty-input",
        "malformed-input",
        "unsafe-input",
        "invalid-record",
        "artifact-publication-failed",
        "output-exists",
    ]
    message: str = Field(min_length=1)
    tool: Literal["nuclei", "trivy", "semgrep"] | None = None
    item: int | None = Field(default=None, ge=1)


class _MalformedJson(ValueError):
    """A JSON syntax, encoding, or non-finite-number failure before schema validation."""


class Week1SubmissionFinding(BaseModel):
    """One safe projection of one admitted datum from a Week-1 submission."""

    model_config = _FORBID
    schema_version: Literal["week1-submission/v1"] = "week1-submission/v1"
    provenance_kind: Literal["week1-submission"] = "week1-submission"
    finding_id: str = Field(min_length=16)
    source_id: str = Field(min_length=32)
    source_ids: list[str] = Field(min_length=1, max_length=1)
    tool: Literal["nuclei", "trivy", "semgrep"]
    scanner: Literal["DAST", "SAST", "SCA"]
    title: str = Field(min_length=1)
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    location: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)

    @field_validator("source_ids", "evidence")
    @classmethod
    def _unique_values(cls, values: list[str]) -> list[str]:
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError("evidence must contain non-empty strings")
        if len(values) != len(set(values)):
            raise ValueError("evidence must be unique")
        return values


class Week1ToolCounts(BaseModel):
    model_config = _FORBID
    input: int = Field(ge=0)
    admitted: int = Field(ge=0)
    refused: int = Field(ge=0)


class Week1InputMetadata(BaseModel):
    model_config = _FORBID
    tool: Literal["nuclei", "trivy", "semgrep"]
    filename: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_kind: Literal["week1-submission"] = "week1-submission"
    input_count: int = Field(ge=0)
    admitted_count: int = Field(ge=0)
    refused_count: int = Field(ge=0)
    counts: Week1ToolCounts


class Week1AggregateCounts(BaseModel):
    model_config = _FORBID
    input: int = Field(ge=0)
    admitted: int = Field(ge=0)
    refused: int = Field(ge=0)
    per_tool: dict[Literal["nuclei", "trivy", "semgrep"], Week1ToolCounts]


class Week1AggregateManifest(BaseModel):
    """Input provenance and counts for a complete Week-1 aggregate."""

    model_config = _FORBID
    schema_version: Literal["week1-submission/v1"] = "week1-submission/v1"
    source_kind: Literal["week1-submission"] = "week1-submission"
    aggregate_count: int = Field(ge=0)
    inputs: list[Week1InputMetadata] = Field(min_length=3, max_length=3)
    counts: Week1AggregateCounts

    @field_validator("inputs")
    @classmethod
    def _canonical_inputs(cls, values: list[Week1InputMetadata]) -> list[Week1InputMetadata]:
        if [value.tool for value in values] != ["nuclei", "trivy", "semgrep"]:
            raise ValueError("manifest inputs must use canonical tool order")
        return values


@dataclass(frozen=True)
class Week1ImportResult:
    records: list[Week1SubmissionFinding]
    manifest: Week1AggregateManifest | None
    failure: Week1ImportFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None


def _failure(
    code: Literal[
        "empty-input", "malformed-input", "unsafe-input", "invalid-record",
        "artifact-publication-failed", "output-exists",
    ],
    message: str,
    *,
    tool: Literal["nuclei", "trivy", "semgrep"] | None = None,
    item: int | None = None,
) -> Week1ImportResult:
    return Week1ImportResult([], None, Week1ImportFailure(code=code, message=message, tool=tool, item=item))


def _bounded_value(value: object, *, depth: int = 0) -> None:
    """Reject parser bombs before format-specific validation."""
    if depth > _MAX_DEPTH:
        raise ValueError("input nesting exceeds the limit")
    if isinstance(value, str):
        if len(value) > _MAX_STRING_CHARS:
            raise ValueError("input string exceeds the limit")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        if len(value) > _MAX_RECORDS:
            raise ValueError("input list exceeds the record limit")
        for item in value:
            _bounded_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > _MAX_RECORDS:
            raise ValueError("input object exceeds the field limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > _MAX_STRING_CHARS:
                raise ValueError("input object key is invalid")
            _bounded_value(item, depth=depth + 1)
        return
    raise ValueError("input uses an unsupported JSON value")


def _read_canonical_file(submission_dir: str | Path, relative: str) -> bytes:
    """Read a bounded ordinary input through no-follow directory descriptors.

    Every path component is opened relative to an already-open parent
    descriptor.  This avoids the check-then-open race of ``lstat(path)`` then
    ``open(path)``: replacing ``scanners`` or ``out`` after its check cannot
    redirect a later lookup outside the submission directory.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | nofollow
    # O_NONBLOCK makes opening a malicious FIFO non-blocking; fstat below then
    # rejects it as non-regular before any bytes are read.
    file_flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | nofollow
    if not nofollow:
        raise PermissionError("platform does not support no-follow input opening")

    root = Path(submission_dir)
    root_parts = root.parts
    input_parts = Path(relative).parts
    if any(part in {"", ".", ".."} for part in root_parts):
        raise PermissionError("submission directory path is unsafe")
    if root.is_absolute():
        current_fd = os.open("/", directory_flags)
        root_parts = root_parts[1:]
    else:
        current_fd = os.open(".", directory_flags)
    try:
        for component in root_parts:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except FileNotFoundError as exc:
                raise FileNotFoundError("submission directory is missing") from exc
            except OSError as exc:
                raise PermissionError("submission directory is unsafe") from exc
            os.close(current_fd)
            current_fd = next_fd
        for component in input_parts[:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except FileNotFoundError as exc:
                raise FileNotFoundError("canonical submitted input is missing") from exc
            except OSError as exc:
                raise PermissionError("canonical submitted input parent is unsafe") from exc
            os.close(current_fd)
            current_fd = next_fd
        try:
            fd = os.open(input_parts[-1], file_flags, dir_fd=current_fd)
        except FileNotFoundError as exc:
            raise FileNotFoundError("canonical submitted input is missing") from exc
        except OSError as exc:
            raise PermissionError("canonical submitted input is unsafe") from exc
        try:
            status = os.fstat(fd)
            if not stat.S_ISREG(status.st_mode):
                raise PermissionError("canonical submitted input is not a regular file")
            if status.st_size > _INPUT_LIMIT_BYTES:
                raise ValueError("canonical submitted input exceeds the byte limit")
            chunks: list[bytes] = []
            remaining = status.st_size + 1
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != status.st_size or len(data) > _INPUT_LIMIT_BYTES:
                raise ValueError("canonical submitted input changed while being read")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(current_fd)


def _decode_json(data: bytes) -> object:
    def reject_constant(_: str) -> object:
        raise ValueError("non-finite JSON number is forbidden")

    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(text, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _MalformedJson("input is not strict UTF-8 JSON") from exc
    _bounded_value(value)
    return value


def _safe_retained_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    clean = _redact_persisted(value) or ""
    if not _REDACTION_TOKEN.sub("", clean).strip():
        raise ValueError(f"{label} has no safe content after redaction")
    return clean


def _redact_persisted(text: str | None) -> str | None:
    """Offline equivalent of :func:`agent.trace.redact_persisted`."""
    if not text:
        return text
    secrets_removed = _SECRET_PATTERNS.sub("[redacted:secret]", text)
    target_removed = _TARGET_RAW_PATTERNS.sub("[redacted:target-raw]", secrets_removed)
    instruction_removed = _SCANNER_INSTRUCTION_PATTERNS.sub("[redacted:target-raw]", target_removed)
    locator_removed = _URL.sub("[redacted:locator]", instruction_removed)
    locator_removed = _IPV4.sub("[redacted:locator]", locator_removed)
    locator_removed = _HOSTNAME.sub("[redacted:locator]", locator_removed)
    locator_removed = _ABSOLUTE_PATH.sub("[redacted:locator]", locator_removed)
    return pii.scrub(locator_removed)


def _severity(value: object, *, semgrep: bool = False) -> Literal["Critical", "High", "Medium", "Low", "Info"]:
    if not isinstance(value, str):
        raise ValueError("severity is unknown")
    resolved = (_SEMGREP_SEVERITIES.get(value.upper()) if semgrep else _SEVERITIES.get(value.lower()))
    if resolved is None:
        raise ValueError("severity is unknown")
    return resolved  # type: ignore[return-value]


def _source_id(tool: Literal["nuclei", "trivy", "semgrep"], digest: str, item: int) -> str:
    return f"week1-submission:{tool}:sha256:{digest}:item:{item}"


def _finding(
    *,
    source_id: str,
    tool: Literal["nuclei", "trivy", "semgrep"],
    scanner: Literal["DAST", "SAST", "SCA"],
    title: str,
    severity: Literal["Critical", "High", "Medium", "Low", "Info"],
    location: str,
    evidence: list[str],
) -> Week1SubmissionFinding:
    key = json.dumps(
        {
            "source_id": source_id,
            "tool": tool,
            "scanner": scanner,
            "title": title,
            "severity": severity,
            "location": location,
            "evidence": evidence,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return Week1SubmissionFinding(
        finding_id="week1-finding:" + hashlib.sha256(key.encode("utf-8")).hexdigest(),
        source_id=source_id,
        source_ids=[source_id],
        tool=tool,
        scanner=scanner,
        title=title,
        severity=severity,
        location=location,
        evidence=list(dict.fromkeys(evidence)),
    )


def _http_path(value: object) -> str:
    if not isinstance(value, str) or _CONTROL.search(value) or "%" in value or "?" in value or "#" in value:
        raise ValueError("HTTP locator is not canonical")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError("HTTP locator is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.netloc != "127.0.0.1:13000"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 13000
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (parsed.path and not parsed.path.startswith("/"))
        or "\\" in parsed.path
    ):
        raise ValueError("HTTP locator is not the submitted loopback origin")
    if urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")) != value:
        raise ValueError("HTTP locator is not canonical")
    path = parsed.path or "/"
    segments = path.split("/")
    if any(segment in {".", ".."} for segment in segments) or "//" in path:
        raise ValueError("HTTP path is not canonical")
    return f"path:{path}"


def _nuclei_records(data: bytes, digest: str) -> list[Week1SubmissionFinding]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Nuclei input is not strict UTF-8") from exc
    lines = text.splitlines()
    if not lines:
        raise EOFError("Nuclei input contained no records")
    if len(lines) > _MAX_RECORDS:
        raise ValueError("Nuclei input exceeds the record limit")

    records: list[Week1SubmissionFinding] = []
    for item, raw in enumerate(lines, start=1):
        if not raw.strip():
            raise ValueError("Nuclei JSONL does not permit blank lines")
        try:
            row = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError("Nuclei input contains invalid JSONL") from exc
        _bounded_value(row)
        if not isinstance(row, dict):
            raise ValueError("Nuclei item must be an object")
        record_type = row.get("type")
        if record_type not in {"http", "javascript"}:
            raise ValueError("Nuclei item type is unsupported")
        allowed = (
            {"host", "info", "matched-at", "matcher-name", "template", "template-id", "timestamp", "type"}
            if record_type == "http"
            else {"host", "info", "matched-at", "template", "template-id", "timestamp", "type"}
        )
        required = {"host", "info", "matched-at", "template", "template-id", "timestamp", "type"}
        if not required.issubset(row) or not set(row).issubset(allowed):
            raise ValueError("Nuclei item schema mismatched")
        if not all(isinstance(row[key], str) and row[key] for key in required - {"info"}):
            raise ValueError("Nuclei scalar field is invalid")
        info = row["info"]
        if not isinstance(info, dict):
            raise ValueError("Nuclei info must be an object")
        allowed_info = (
            {"name", "severity", "description", "tags", "classification"}
            if record_type == "http"
            else {"name", "severity", "description", "tags"}
        )
        if not {"name", "severity"}.issubset(info) or not set(info).issubset(allowed_info):
            raise ValueError("Nuclei info schema mismatched")
        if "tags" in info and (
            not isinstance(info["tags"], list) or not all(isinstance(tag, str) for tag in info["tags"])
        ):
            raise ValueError("Nuclei info tags are invalid")
        if "description" in info and not isinstance(info["description"], str):
            raise ValueError("Nuclei description is invalid")
        if "classification" in info and not isinstance(info["classification"], dict):
            raise ValueError("Nuclei classification is invalid")
        source_id = _source_id("nuclei", digest, item)
        title = _safe_retained_text(info["name"], "Nuclei name")
        severity = _severity(info["severity"])
        template_id = _safe_retained_text(row["template-id"], "Nuclei template id")
        evidence = [f"template-id={template_id}"]
        if record_type == "http":
            if "matcher-name" in row:
                matcher = _safe_retained_text(row["matcher-name"], "Nuclei matcher name")
                evidence.append(f"matcher-name={matcher}")
            location = _http_path(row["matched-at"])
        else:
            # Do not retain Javascript records' host or matched-at values.
            location = f"nuclei-js:{digest[:16]}:item:{item}"
        records.append(
            _finding(
                source_id=source_id,
                tool="nuclei",
                scanner="DAST",
                title=title,
                severity=severity,
                location=location,
                evidence=evidence,
            )
        )
    return records


def _integer(value: object, label: str, *, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} is invalid")
    return value


def _relative_location(value: object, *, prefix: str, opaque: str) -> str:
    """Project a scanner target only if it is a safe, relative logical path."""
    if not isinstance(value, str) or not value or _CONTROL.search(value) or "\\" in value:
        return opaque
    candidate = Path(value)
    if candidate.is_absolute():
        return opaque
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return opaque
    # A dotted or port-like component is ambiguous: it can be an extension, but
    # it can also be an attacker-supplied hostname/IP literal.  The aggregate
    # has no need to disclose either, so use its provenance locator instead.
    if any("." in part or ":" in part or part.lower() == "localhost" for part in parts):
        return opaque
    return f"{prefix}{value}"


def _trivy_evidence(kind: str, issue: dict[str, Any]) -> list[str]:
    if kind == "Vulnerabilities":
        values: list[tuple[str, object]] = [
            ("vulnerability-id", issue["VulnerabilityID"]),
            ("package", issue["PkgName"]),
        ]
        for source, label in (("InstalledVersion", "installed-version"), ("FixedVersion", "fixed-version")):
            if source in issue:
                values.append((label, issue[source]))
    elif kind == "Secrets":
        values = [("rule-id", issue["RuleID"])]
        if "Category" in issue:
            values.append(("category", issue["Category"]))
        if "StartLine" in issue or "EndLine" in issue:
            start = _integer(issue.get("StartLine"), "Trivy StartLine")
            end = _integer(issue.get("EndLine"), "Trivy EndLine")
            if end < start:
                raise ValueError("Trivy EndLine is before StartLine")
            values.append(("line-range", f"{start}-{end}"))
    else:
        values = [("id", issue["ID"])]
        if "AVDID" in issue:
            values.append(("avd-id", issue["AVDID"]))
    kind_name = {
        "Vulnerabilities": "vulnerability",
        "Secrets": "secret",
        "Misconfigurations": "misconfiguration",
    }[kind]
    evidence = [f"trivy-kind={kind_name}"]
    evidence.extend(f"{label}={_safe_retained_text(raw, f'Trivy {label}')}" for label, raw in values)
    return list(dict.fromkeys(evidence))


def _trivy_records(value: object, digest: str) -> list[Week1SubmissionFinding]:
    if not isinstance(value, dict) or set(value) != _TRIVY_ROOT_FIELDS:
        raise ValueError("Trivy root schema mismatched")
    if value.get("SchemaVersion") != 2 or value.get("ArtifactType") not in {"container_image", "filesystem"}:
        raise ValueError("Trivy root values mismatched")
    _safe_retained_text(value.get("ArtifactName"), "Trivy ArtifactName")
    results = value.get("Results")
    if not isinstance(results, list) or not results:
        raise EOFError("Trivy input contained no results")
    records: list[Week1SubmissionFinding] = []
    item = 0
    for result in results:
        if (
            not isinstance(result, dict)
            or not {"Target", "Class", "Vulnerabilities", "Secrets", "Misconfigurations"}.issubset(result)
            or not set(result).issubset(_TRIVY_RESULT_FIELDS)
        ):
            raise ValueError("Trivy result schema mismatched")
        if result.get("Class") not in {"secret", "config", "lang-pkgs", "os-pkgs"}:
            raise ValueError("Trivy result class is unsupported")
        for kind in ("Vulnerabilities", "Secrets", "Misconfigurations"):
            issues = result.get(kind)
            if not isinstance(issues, list):
                raise ValueError(f"Trivy {kind} must be a list")
            for issue in issues:
                item += 1
                if not isinstance(issue, dict) or not set(issue).issubset(_TRIVY_ISSUE_FIELDS[kind]):
                    raise ValueError(f"Trivy {kind} schema mismatched")
                if not _TRIVY_REQUIRED_FIELDS[kind].issubset(issue):
                    raise ValueError(f"Trivy {kind} required field missing")
                source_id = _source_id("trivy", digest, item)
                title = _safe_retained_text(issue["Title"], "Trivy title")
                severity = _severity(issue["Severity"])
                location = _relative_location(
                    result.get("Target"),
                    prefix="file:",
                    opaque=f"trivy:{digest[:16]}:item:{item}",
                )
                records.append(
                    _finding(
                        source_id=source_id,
                        tool="trivy",
                        scanner="SCA" if kind == "Vulnerabilities" else "SAST",
                        title=title,
                        severity=severity,
                        location=location,
                        evidence=_trivy_evidence(kind, issue),
                    )
                )
    if not records:
        raise EOFError("Trivy input contained no findings")
    return records


def _safe_semgrep_relative(value: str) -> str:
    if not value or _CONTROL.search(value) or "\\" in value:
        raise ValueError("Semgrep path is unsafe")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Semgrep path is unsafe")
    return value


def _relative_file_or_opaque(value: str, *, prefix: str, opaque: str) -> str:
    safe = _safe_semgrep_relative(value)
    if any("." in part or ":" in part or part.lower() == "localhost" for part in safe.split("/")):
        return opaque
    return f"{prefix}{safe}"


def _semgrep_location(value: object, source_root: Path | None, digest: str, item: int) -> str:
    if not isinstance(value, str):
        raise ValueError("Semgrep path is invalid")
    if _CONTROL.search(value) or "\\" in value:
        raise ValueError("Semgrep path is unsafe")
    candidate = Path(value)
    opaque = f"semgrep:{digest[:16]}:item:{item}"
    if not candidate.is_absolute():
        return _relative_file_or_opaque(value, prefix="file:", opaque=opaque)
    if source_root is not None:
        try:
            resolved_candidate = candidate.resolve(strict=True)
            relative = resolved_candidate.relative_to(source_root)
            return _relative_file_or_opaque(relative.as_posix(), prefix="file:", opaque=opaque)
        except (OSError, ValueError):
            pass
    return opaque


def _semgrep_position(value: object, label: str) -> int:
    if not isinstance(value, dict) or set(value) != {"line", "col", "offset"}:
        raise ValueError(f"Semgrep {label} schema mismatched")
    _integer(value.get("col"), f"Semgrep {label} column")
    _integer(value.get("offset"), f"Semgrep {label} offset", minimum=0)
    return _integer(value.get("line"), f"Semgrep {label} line")


def _semgrep_records(value: object, digest: str, source_root: Path | None) -> list[Week1SubmissionFinding]:
    if not isinstance(value, dict) or set(value) != {"errors", "results", "version"}:
        raise ValueError("Semgrep root schema mismatched")
    if not isinstance(value["version"], str) or not value["version"]:
        raise ValueError("Semgrep version is invalid")
    if not isinstance(value["errors"], list) or value["errors"]:
        raise ValueError("Semgrep input contains errors")
    results = value["results"]
    if not isinstance(results, list) or not results:
        raise EOFError("Semgrep input contained no results")
    records: list[Week1SubmissionFinding] = []
    for item, result in enumerate(results, start=1):
        if not isinstance(result, dict) or set(result) != {"check_id", "path", "start", "end", "extra"}:
            raise ValueError("Semgrep result schema mismatched")
        extra = result["extra"]
        if not isinstance(extra, dict) or set(extra) != {"lines", "message", "metadata", "severity"}:
            raise ValueError("Semgrep extra schema mismatched")
        # `message` and `lines` are intentionally inspected only as bounded JSON values above;
        # neither is projected or used to construct any persisted string.
        if not isinstance(extra["metadata"], dict):
            raise ValueError("Semgrep metadata is invalid")
        start = _semgrep_position(result["start"], "start")
        end = _semgrep_position(result["end"], "end")
        if end < start:
            raise ValueError("Semgrep end line is before start line")
        rule_id = _safe_retained_text(result["check_id"], "Semgrep rule id")
        severity = _severity(extra["severity"], semgrep=True)
        source_id = _source_id("semgrep", digest, item)
        records.append(
            _finding(
                source_id=source_id,
                tool="semgrep",
                scanner="SAST",
                title=rule_id,
                severity=severity,
                location=_semgrep_location(result["path"], source_root, digest, item),
                evidence=[f"rule-id={rule_id}", f"severity={severity}", f"line-range={start}-{end}"],
            )
        )
    return records


def _counts(records: list[Week1SubmissionFinding]) -> Week1AggregateCounts:
    per_tool: dict[Literal["nuclei", "trivy", "semgrep"], Week1ToolCounts] = {}
    for tool in ("nuclei", "trivy", "semgrep"):
        count = sum(record.tool == tool for record in records)
        per_tool[tool] = Week1ToolCounts(input=count, admitted=count, refused=0)
    total = len(records)
    return Week1AggregateCounts(input=total, admitted=total, refused=0, per_tool=per_tool)


def normalize_week1_submission(
    submission_dir: str | Path, *, semgrep_source_root: str | Path | None = None,
) -> Week1ImportResult:
    """Load, validate, and safely project all three canonical Week-1 artifacts in memory."""
    source_root: Path | None = None
    if semgrep_source_root is not None:
        try:
            source_root = Path(semgrep_source_root).resolve(strict=True)
            if not source_root.is_dir():
                raise OSError("not a directory")
        except OSError:
            # The caller may still import all evidence with opaque Semgrep locations.
            source_root = None

    payloads: dict[str, tuple[bytes, str]] = {}
    for tool, relative, _ in _CANONICAL_INPUTS:
        try:
            data = _read_canonical_file(submission_dir, relative)
        except FileNotFoundError:
            return _failure("malformed-input", "a canonical submitted input is missing", tool=tool)  # type: ignore[arg-type]
        except PermissionError:
            return _failure("unsafe-input", "a canonical submitted input is unsafe", tool=tool)  # type: ignore[arg-type]
        except (OSError, ValueError):
            return _failure("malformed-input", "a canonical submitted input could not be read", tool=tool)  # type: ignore[arg-type]
        payloads[tool] = (data, hashlib.sha256(data).hexdigest())

    try:
        nuclei = _nuclei_records(*payloads["nuclei"])
    except EOFError:
        return _failure("empty-input", "Nuclei submitted input is empty", tool="nuclei")
    except ValueError:
        return _failure("invalid-record", "Nuclei submitted input is invalid", tool="nuclei")
    try:
        trivy_root = _decode_json(payloads["trivy"][0])
        trivy = _trivy_records(trivy_root, payloads["trivy"][1])
    except EOFError:
        return _failure("empty-input", "Trivy submitted input is empty", tool="trivy")
    except _MalformedJson:
        return _failure("malformed-input", "Trivy submitted input is malformed", tool="trivy")
    except ValueError:
        return _failure("invalid-record", "Trivy submitted input is invalid", tool="trivy")
    try:
        semgrep_root = _decode_json(payloads["semgrep"][0])
        semgrep = _semgrep_records(semgrep_root, payloads["semgrep"][1], source_root)
    except EOFError:
        return _failure("empty-input", "Semgrep submitted input is empty", tool="semgrep")
    except _MalformedJson:
        return _failure("malformed-input", "Semgrep submitted input is malformed", tool="semgrep")
    except ValueError:
        return _failure("invalid-record", "Semgrep submitted input is invalid", tool="semgrep")

    records = nuclei + trivy + semgrep
    if not records or len(records) > _MAX_RECORDS:
        return _failure("empty-input", "submitted inputs produced no records")
    counts = _counts(records)
    inputs = [
        Week1InputMetadata(
            tool=tool,
            filename=relative,
            sha256=payloads[tool][1],
            input_count=counts.per_tool[tool].input,
            admitted_count=counts.per_tool[tool].admitted,
            refused_count=counts.per_tool[tool].refused,
            counts=counts.per_tool[tool],
        )
        for tool, relative, _ in _CANONICAL_INPUTS
    ]
    return Week1ImportResult(
        records,
        Week1AggregateManifest(aggregate_count=len(records), inputs=inputs, counts=counts),
    )


def _destination_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def _stage_json(destination: Path, data: bytes) -> Path:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.stage.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return Path(temporary)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _remove_if_ours(destination: Path, staged: Path) -> None:
    try:
        if destination.exists() and os.path.samestat(destination.stat(), staged.stat()):
            destination.unlink()
    except FileNotFoundError:
        pass


def _publish_pair_exclusive(output: Path, output_data: bytes, manifest: Path, manifest_data: bytes) -> None:
    if output == manifest:
        raise ValueError("output and manifest paths must differ")
    if not _destination_absent(output) or not _destination_absent(manifest):
        raise FileExistsError("a destination already exists")

    output_stage: Path | None = None
    manifest_stage: Path | None = None
    output_published = False
    manifest_published = False
    try:
        output_stage = _stage_json(output, output_data)
        manifest_stage = _stage_json(manifest, manifest_data)
        # link(2) creates the final name exclusively, including against symlinks.
        os.link(output_stage, output)
        output_published = True
        os.link(manifest_stage, manifest)
        manifest_published = True
        os.chmod(output, 0o600)
        os.chmod(manifest, 0o600)
    except Exception:
        if output_published and output_stage is not None:
            _remove_if_ours(output, output_stage)
        if manifest_published and manifest_stage is not None:
            _remove_if_ours(manifest, manifest_stage)
        raise
    finally:
        for staged in (output_stage, manifest_stage):
            if staged is not None:
                try:
                    staged.unlink()
                except FileNotFoundError:
                    pass


def normalize_week1_submission_to_files(
    submission_dir: str | Path,
    output_jsonl: str | Path,
    output_manifest: str | Path,
    *,
    semgrep_source_root: str | Path | None = None,
) -> Week1ImportResult:
    """Validate all inputs first, then exclusively publish the aggregate and manifest together."""
    result = normalize_week1_submission(submission_dir, semgrep_source_root=semgrep_source_root)
    if not result.ok:
        return result
    assert result.manifest is not None
    jsonl = b"".join(
        record.model_dump_json(exclude_none=True).encode("utf-8") + b"\n" for record in result.records
    )
    manifest_data = (
        result.manifest.model_dump_json(exclude_none=True, indent=2).encode("utf-8") + b"\n"
    )
    try:
        _publish_pair_exclusive(Path(output_jsonl), jsonl, Path(output_manifest), manifest_data)
    except FileExistsError:
        return _failure("output-exists", "an output destination already exists")
    except (OSError, ValueError):
        return _failure("artifact-publication-failed", "aggregate outputs could not be published")
    return result


def main(argv: list[str] | None = None) -> int:
    """CLI for the Week-2-only submitted-artifact compatibility importer."""
    parser = argparse.ArgumentParser(
        description="Normalize only the canonical sanitized Week-1 submission artifacts into a Week-2 aggregate."
    )
    parser.add_argument("--submission-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", "--manifest-output", dest="manifest", required=True)
    parser.add_argument("--semgrep-source-root")
    args = parser.parse_args(argv)
    result = normalize_week1_submission_to_files(
        args.submission_dir,
        args.output,
        args.manifest,
        semgrep_source_root=args.semgrep_source_root,
    )
    if not result.ok:
        assert result.failure is not None
        print(json.dumps({"status": "failed", "failure": result.failure.code}, sort_keys=True))
        return 1
    print(json.dumps({"status": "ok", "records": len(result.records)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
