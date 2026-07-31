"""Structural PII redaction for target-derived text (Week-9, decision 0017).

This module is the Week-9 counterpart to `infra/litellm/guardrails/egress_redaction.py` and
`agent/trace.py`: where those strip *credentials* this host holds and *attack-shaped* target-raw
markers, this one strips *personal data* that a (simulated) pentest dump surfaces from the target's
mock user store — emails, credit-card PANs, session JWTs, UUIDs — before that text can reach the
Supervisor checkpoint, the approval-audit ledger, the console, the Phoenix traces, or the RAG store.

It follows the SAME discipline egress_redaction.py documents at length, for the same reason: the
agent's legitimate workload is SQL-injection payloads, XSS strings, path traversal, stack traces,
and file hashes — the actual work product. A redactor tuned to "anything that looks like data"
mangles that workload, and a guardrail that quietly corrupts a finding degrades every downstream
result invisibly. So every detector here matches a NARROW STRUCTURAL SHAPE, never "suspicious
looking" content:

- **email** — a local-part@domain.tld shape. Attack payloads do not carry this shape.
- **credit-card PAN** — 13–19 digits that pass the Luhn checksum AND sit under a card-ish label
  (`card_number=`, `"pan":`, …). The label anchor is load-bearing, not cosmetic: ~1 in 10 random
  16-digit numbers pass Luhn by chance, so a bare-number rule would redact a `session_id` or a file
  offset. Requiring the label means a non-card 16-digit identifier is never touched. A *bare* PAN in
  a positional multi-row SQL result (column named once in a header row) is a deliberate, documented
  gap — bound to the deferred real-execution work (decision 0016), not closed by broadening here.
- **JWT** — the `eyJ…`.`…`.`…` three-segment base64url shape (same anchor egress_redaction uses to
  avoid the length-only false positive on Java dotted identifiers).
- **UUID** — RFC 4122 layout.

Deliberately NOT redacted (documented non-goals, so a reader knows these are choices):
- **Bare 32-char MD5 password hashes.** A standalone 32-hex string is UUID-hex territory and
  redacting it would false-positive on legitimate hashes; the *value* is instead removed by the
  existing credential-assignment pass (`password=<md5>` → `[redacted:secret]` in `agent/trace.py`),
  and the "weak unsalted hashing" FINDING survives via the finding's class label + column +
  endpoint, which never needed the literal digest (decision 0017, W9-D2a).
- **64-char hex file hashes / long numeric IDs without a card label.** Preserved as evidence, same
  as egress_redaction.py.

The redactor records only the CLASS and a COUNT of what it removed — never the value, a substring,
or a hash of it (a hash of short PII is brute-forceable, defeating the point — egress_redaction's
own reasoning). Kept free of any third-party import so it is pure, testable without services, and
has no supply-chain surface of its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PiiFinding:
    """What a redaction pass removed: the class and how many, never the value."""

    cls: str
    count: int


def _placeholder(cls: str) -> str:
    return f"[redacted:pii:{cls}]"


# --- detectors ---------------------------------------------------------------------------------
# Applied in the order below. There is no cross-detector collision (a JWT's base64url body has no
# `@`, an email has no three-dot JWT shape, a UUID is hex-with-hyphens, a card is label-anchored
# digits) so the order is for readability, not correctness — but PII as a whole must run LAST
# relative to the secret/target-raw passes in agent/trace.py (see that module) so an already-placed
# `[redacted:pii:*]` token is never re-matched by the greedy credential-assignment rule.

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")

_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# Card: a card-ish KEY, optional quote, then 13–19 digits with optional single space/hyphen
# separators. The digits are Luhn-checked at substitution time; a label match that fails Luhn is
# left untouched (it was not a card). `session_id`, `user_id`, offsets etc. never match because
# their key is not card-ish.
_CARD_LABELED = re.compile(
    r"(?P<key>\b(?:card(?:[_\s\-]?(?:number|no|num|pan))?|pan|ccnum|cc[_\s\-]?number"
    r"|credit[_\s\-]?card)\b[\"']?\s*[:=]\s*[\"']?)"
    # Separators tolerated between digit groups: space, hyphen, dot, underscore. Widened past the
    # obvious space/hyphen so a `4532.0151.1283.0366` under a card label can't evade — safe because
    # BOTH the card-ish label anchor above AND the Luhn check below still gate every match, so a
    # non-card dotted number (a version, an IP) never reaches this rule.
    r"(?P<num>\d(?:[ \-._]?\d){12,18})",
    re.IGNORECASE,
)

# A phone-shaped value is sensitive only when it is labelled as a telephone number. This avoids
# corrupting scanner ports, payload lengths, and numeric security evidence.
_PHONE_LABELED = re.compile(
    r"(?P<key>\b(?:phone|telephone|tel|mobile|msisdn)\b[\"']?\s*[:=]\s*[\"']?)"
    r"(?P<num>\+?\d(?:[ .()\-]?\d){7,14})",
    re.IGNORECASE,
)


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum over the bare digit string (separators already stripped)."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str | None) -> tuple[str | None, list[PiiFinding]]:
    """Redact PII shapes in `text`, returning `(scrubbed_text, findings)`. `findings` names the
    class + count removed so a caller can audit WHAT was stripped without ever handling the value.
    Non-str / empty input is returned unchanged with no findings."""
    if not text:
        return text, []

    findings: list[PiiFinding] = []

    def _count_sub(pattern: re.Pattern[str], cls: str, repl) -> None:
        nonlocal text
        n = 0

        def _r(m: re.Match[str]) -> str:
            nonlocal n
            out = repl(m)
            if out is not None:
                n += 1
                return out
            return m.group(0)  # matched the label but not a real card — leave untouched

        text = pattern.sub(_r, text)  # type: ignore[arg-type]
        if n:
            findings.append(PiiFinding(cls, n))

    # Card first (label-anchored, Luhn-gated), then the unambiguous structural shapes.
    def _card_repl(m: re.Match[str]) -> str | None:
        bare = re.sub(r"[ \-._]", "", m.group("num"))
        if _luhn_ok(bare):
            return m.group("key") + _placeholder("card")
        return None

    _count_sub(_CARD_LABELED, "card", _card_repl)

    # A tabular response names a card column once and then carries bare values on later rows.
    # Do not use a global bare-PAN rule: redact only the field under an explicit card header.
    lines = text.splitlines(keepends=True)
    if len(lines) >= 2:
        for header_no, header in enumerate(lines[:-1]):
            found: tuple[int, str] | None = None
            for delimiter in ("\t", "|", ","):
                fields = [part.strip().lower() for part in header.rstrip("\r\n").split(delimiter)]
                matches = [index for index, field in enumerate(fields)
                           if re.fullmatch(r"(?:card(?:[_\s-]?(?:number|no|num|pan))?|pan|ccnum|"
                                           r"cc[_\s-]?number|credit[_\s-]?card)", field)]
                if len(matches) == 1 and len(fields) > 1:
                    found = (matches[0], delimiter)
                    break
            if found is None:
                continue
            card_index, delimiter = found
            for row_no in range(header_no + 1, len(lines)):
                ending = "\n" if lines[row_no].endswith("\n") else ""
                fields = lines[row_no].rstrip("\r\n").split(delimiter)
                if len(fields) <= card_index:
                    continue
                bare = re.sub(r"[ ._\-]", "", fields[card_index].strip())
                if _luhn_ok(bare):
                    fields[card_index] = _placeholder("card")
                    lines[row_no] = delimiter.join(fields) + ending
                    findings.append(PiiFinding("card", 1))
            break
        text = "".join(lines)

    def _phone_repl(m: re.Match[str]) -> str | None:
        digits = re.sub(r"\D", "", m.group("num"))
        if 8 <= len(digits) <= 15:
            return m.group("key") + _placeholder("phone")
        return None

    _count_sub(_PHONE_LABELED, "phone", _phone_repl)
    _count_sub(_EMAIL, "email", lambda m: _placeholder("email"))
    _count_sub(_JWT, "jwt", lambda m: _placeholder("jwt"))
    _count_sub(_UUID, "uuid", lambda m: _placeholder("uuid"))

    return text, findings


def scrub(text: str | None) -> str | None:
    """Text-only convenience for composition into agent/trace.py's scalar scrub (findings dropped).
    See `redact` for the audited form used at the capture boundary."""
    return redact(text)[0]
