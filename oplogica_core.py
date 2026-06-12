"""Oplogica core library.

Deterministic primitives for evidence integrity and reviewable decision records.

Design constraints:
- Zero ComfyUI imports. Zero third-party imports. Standard library only.
- Every function is deterministic given its inputs (except explicit timestamp helpers).
- This module is intentionally liftable into the OVA Verification API unchanged.

Scope statement (do not remove):
    Records produced by this library are tamper-evident.
    They do not establish truth, fairness, correctness, or legal sufficiency.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac as _hmac
import json
import os
import sys
import uuid

SCHEMA_RECORD = "oplogica.decision_record.v1"
SCHEMA_TASK = "oplogica.task.v1"
SCHEMA_EVIDENCE = "oplogica.evidence_item.v1"
SCHEMA_BUNDLE = "oplogica.evidence_bundle.v1"
SCHEMA_APPROVAL = "oplogica.approval.v2"
SCHEMA_POLICY_RESULT = "oplogica.policy_result.v1"

GENESIS = "GENESIS"
PACK_VERSION = "1.0.0"

INTEGRITY_SCOPE = (
    "Tamper-evident record. Integrity is not truth: this record does not "
    "establish correctness, fairness, or legal sufficiency."
)


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Current UTC time, second precision, ISO 8601 with Z suffix."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str):
    """Parse an ISO 8601 timestamp. Returns aware datetime or None."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def age_days(timestamp: str):
    """Age in days of an ISO timestamp relative to now. None if unparseable."""
    dt = parse_iso(timestamp)
    if dt is None:
        return None
    delta = datetime.datetime.now(datetime.timezone.utc) - dt
    return round(delta.total_seconds() / 86400.0, 3)


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def canonical_json(obj) -> str:
    """Deterministic JSON serialization: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    """SHA-256 over the canonical JSON form of any JSON-serializable object."""
    return sha256_hex(canonical_json(obj))


def short_hash(h, head: int = 12, tail: int = 8) -> str:
    if not h:
        return ""
    if len(h) <= head + tail + 3:
        return h
    return h[:head] + "..." + h[-tail:]


# ---------------------------------------------------------------------------
# Merkle
# ---------------------------------------------------------------------------

def merkle_root(leaf_hashes) -> str:
    """Merkle root over an ordered list of hex hashes.

    Empty list returns a fixed sentinel hash. Odd levels duplicate the last
    element (Bitcoin-style padding).
    """
    if not leaf_hashes:
        return sha256_hex(b"OPLOGICA_EMPTY_BUNDLE")
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# ---------------------------------------------------------------------------
# HMAC signing (explicitly NOT non-repudiation; see README limitations)
# ---------------------------------------------------------------------------

def load_hmac_key(path: str):
    """Load raw key bytes from a file. Returns (key, key_id) or None.

    key_id is the first 12 hex chars of SHA-256(key), safe to publish.
    """
    if not path or not path.strip():
        return None
    p = path.strip()
    if not os.path.isfile(p):
        raise FileNotFoundError(f"HMAC key file not found: {p}")
    with open(p, "rb") as f:
        key = f.read()
    if len(key) < 16:
        raise ValueError("HMAC key must be at least 16 bytes")
    return key, sha256_hex(key)[:12]


def hmac_sign(record_hash: str, key: bytes, key_id: str) -> dict:
    sig = _hmac.new(key, record_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"alg": "HMAC-SHA256", "key_id": key_id, "value": sig}


def hmac_verify(record_hash: str, signature: dict, key: bytes) -> bool:
    if not signature or signature.get("alg") != "HMAC-SHA256":
        return False
    expected = _hmac.new(key, record_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return _hmac.compare_digest(expected, signature.get("value", ""))


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def resolve_output_path(rel_path: str) -> str:
    """Resolve a path under the ComfyUI output directory when available,
    otherwise under ./output. Absolute paths pass through unchanged."""
    if os.path.isabs(rel_path):
        return rel_path
    try:
        import folder_paths  # ComfyUI runtime module
        base = folder_paths.get_output_directory()
    except Exception:
        base = os.path.join(os.getcwd(), "output")
    return os.path.join(base, rel_path)


# ---------------------------------------------------------------------------
# Ledger (append-only JSONL with hash chaining)
# ---------------------------------------------------------------------------

def ledger_read(path: str):
    """Read all records. Unparseable lines are returned as
    {"_parse_error": ..., "_line": index}. Missing file returns []."""
    if not os.path.isfile(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                records.append({"_parse_error": str(e), "_line": i})
    return records


def ledger_tail_hash(path: str) -> str:
    """record_hash of the last valid record, or GENESIS."""
    records = ledger_read(path)
    for rec in reversed(records):
        h = rec.get("integrity", {}).get("record_hash") if isinstance(rec, dict) else None
        if h:
            return h
    return GENESIS


def ledger_append(path: str, record: dict):
    """Append a record after verifying chain consistency against the file
    AS IT EXISTS RIGHT NOW. No in-memory chain state is kept anywhere in
    this module; the tail is re-derived from disk on every call.

    Three outcomes, returned as (position, status):
      (index, "APPENDED")            record written at zero-based index
      (index, "DUPLICATE_SKIPPED")   tail already holds this record_hash
      (-1,    "STALE_PREV_REJECTED") the record's declared
                                     chain.prev_record_hash does not match
                                     the actual current tail (GENESIS for a
                                     missing or empty file). Nothing is
                                     written: a record sealed against a
                                     ledger state that no longer exists
                                     (renamed, deleted, replaced, or
                                     truncated since sealing) must be
                                     re-sealed, never appended, or it would
                                     plant a CHAIN_BREAK in the new file.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    records = ledger_read(path)
    rec_hash = record.get("integrity", {}).get("record_hash")
    if records:
        tail = records[-1]
        if isinstance(tail, dict) and tail.get("integrity", {}).get("record_hash") == rec_hash:
            return len(records) - 1, "DUPLICATE_SKIPPED"
    actual_tail = GENESIS
    for rec in reversed(records):
        h = rec.get("integrity", {}).get("record_hash") if isinstance(rec, dict) else None
        if h:
            actual_tail = h
            break
    declared_prev = record.get("chain", {}).get("prev_record_hash")
    if declared_prev != actual_tail:
        return -1, "STALE_PREV_REJECTED"
    with open(path, "a", encoding="utf-8") as f:
        f.write(canonical_json(record) + "\n")
    return len(records), "APPENDED"


# ---------------------------------------------------------------------------
# Decision record
# ---------------------------------------------------------------------------

def compute_record_hash(record: dict) -> str:
    """Hash over the record excluding the integrity block itself."""
    body = {k: v for k, v in record.items() if k != "integrity"}
    return hash_obj(body)


def seal_record(task: dict, evidence_summary: dict, checks: dict,
                approvals: list, verdict: dict, prev_hash: str,
                signer=None) -> dict:
    """Assemble and seal a decision record.

    signer: optional (key_bytes, key_id) tuple for HMAC signing.
    """
    record = {
        "schema": SCHEMA_RECORD,
        "record_id": str(uuid.uuid4()),
        "created_at": utc_now_iso(),
        "environment": {
            "producer": "oplogica-comfyui",
            "pack_version": PACK_VERSION,
        },
        "task": task,
        "evidence": evidence_summary,
        "checks": checks,
        "approvals": approvals,
        "verdict": verdict,
        "scope": INTEGRITY_SCOPE,
        "chain": {"prev_record_hash": prev_hash or GENESIS},
    }
    record_hash = compute_record_hash(record)
    signature = None
    if signer is not None:
        key, key_id = signer
        signature = hmac_sign(record_hash, key, key_id)
    record["integrity"] = {"record_hash": record_hash, "signature": signature}
    return record


def validate_chain(records, key: bytes = None) -> dict:
    """Validate an ordered list of decision records.

    Checks per record:
      PARSE_ERROR          line was not valid JSON
      HASH_MISMATCH        stored record_hash does not match recomputation
      CHAIN_BREAK          prev_record_hash does not match predecessor
      SIGNATURE_INVALID    HMAC does not verify against provided key
      SIGNATURE_MISSING    key provided but record is unsigned (warning)

    Returns {"valid", "length", "errors", "warnings", "signatures_checked"}.
    """
    errors = []
    warnings = []
    sig_checked = 0
    prev = GENESIS
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or "_parse_error" in rec:
            errors.append({"index": i, "code": "PARSE_ERROR",
                           "detail": rec.get("_parse_error", "not an object")
                           if isinstance(rec, dict) else "not an object"})
            prev = GENESIS  # chain trust is broken past this point
            continue
        stored = rec.get("integrity", {}).get("record_hash", "")
        recomputed = compute_record_hash(rec)
        if stored != recomputed:
            errors.append({"index": i, "code": "HASH_MISMATCH",
                           "detail": f"stored {short_hash(stored)} != "
                                     f"recomputed {short_hash(recomputed)}"})
        declared_prev = rec.get("chain", {}).get("prev_record_hash", "")
        if declared_prev != prev:
            errors.append({"index": i, "code": "CHAIN_BREAK",
                           "detail": f"declares prev {short_hash(declared_prev)}, "
                                     f"expected {short_hash(prev)}"})
        if key is not None:
            sig = rec.get("integrity", {}).get("signature")
            if sig is None:
                warnings.append({"index": i, "code": "SIGNATURE_MISSING",
                                 "detail": "record is unsigned"})
            else:
                sig_checked += 1
                if not hmac_verify(stored, sig, key):
                    errors.append({"index": i, "code": "SIGNATURE_INVALID",
                                   "detail": f"key_id {sig.get('key_id', '?')}"})
        prev = stored
    return {
        "valid": len(errors) == 0,
        "length": len(records),
        "errors": errors,
        "warnings": warnings,
        "signatures_checked": sig_checked,
    }


# ---------------------------------------------------------------------------
# Policy engine (declarative JSON rules)
# ---------------------------------------------------------------------------

def evaluate_policy(policy: dict, task: dict, bundle: dict) -> dict:
    """Evaluate a task plus its evidence bundle against a declarative policy.

    Rules are enforced only when the corresponding policy key is present,
    except completeness which is always enforced. Returns a structured result
    with one entry per evaluated rule.
    """
    checks = []
    requires_human = bool(policy.get("required_approvals", 1) >= 1)

    def add(rule, passed, detail, enforced=True):
        checks.append({"rule": rule, "passed": bool(passed),
                       "detail": detail, "enforced": enforced})

    allowed = policy.get("allowed_actions")
    if allowed is not None:
        ok = task.get("action_type") in allowed
        add("action_allowed", ok,
            f"action_type '{task.get('action_type')}' "
            f"{'is' if ok else 'is NOT'} in allowed_actions")

    limits = policy.get("limits", {})
    max_amount = limits.get("max_amount")
    if max_amount is not None and task.get("amount") is not None:
        ok = float(task["amount"]) <= float(max_amount)
        add("amount_within_limit", ok,
            f"amount {task['amount']} vs max_amount {max_amount}")

    pol_currency = limits.get("currency")
    if pol_currency and task.get("currency"):
        ok = str(task["currency"]).upper() == str(pol_currency).upper()
        add("currency_match", ok,
            f"task currency {task['currency']} vs policy {pol_currency}")

    ev = policy.get("evidence", {})
    stats = bundle.get("stats", {})
    items = bundle.get("items", [])

    min_items = ev.get("min_items")
    if min_items is not None:
        ok = stats.get("unique_count", 0) >= int(min_items)
        add("evidence_min_items", ok,
            f"{stats.get('unique_count', 0)} unique items vs minimum {min_items}")

    if ev.get("require_source"):
        missing = stats.get("missing_source_count", 0)
        add("evidence_sources_present", missing == 0,
            f"{missing} item(s) missing a source reference")

    max_age = ev.get("max_age_days")
    if max_age is not None:
        stale = []
        for it in items:
            a = it.get("age_days")
            if a is None or a > float(max_age):
                stale.append(it.get("item_id", "?"))
        add("evidence_freshness", len(stale) == 0,
            f"{len(stale)} item(s) older than {max_age} days or undated")

    incomplete = stats.get("incomplete_count", 0)
    add("evidence_completeness", incomplete == 0,
        f"{incomplete} item(s) missing claim or content")

    patterns = policy.get("sensitive_patterns", [])
    haystack = (str(task.get("action_type", "")) + " " +
                canonical_json(task.get("payload", {}))).lower()
    hits = [p for p in patterns if p.lower() in haystack]
    if hits:
        requires_human = True
    add("sensitive_action_scan", True,
        f"matched patterns: {hits}" if hits else "no sensitive patterns matched",
        enforced=False)

    passed = all(c["passed"] for c in checks if c["enforced"])
    return {
        "schema": SCHEMA_POLICY_RESULT,
        "policy_id": policy.get("policy_id", "UNSPECIFIED"),
        "policy_version": policy.get("version", "0"),
        "policy_hash": hash_obj(policy),
        "checks": checks,
        "passed": passed,
        "requires_human": requires_human,
        "evaluated_at": utc_now_iso(),
    }


# ---------------------------------------------------------------------------
# CLI: python oplogica_core.py verify <ledger.jsonl> [hmac_key_file]
# ---------------------------------------------------------------------------

def _cli(argv):
    if len(argv) >= 2 and argv[0] == "verify":
        path = argv[1]
        key = None
        if len(argv) >= 3:
            loaded = load_hmac_key(argv[2])
            key = loaded[0] if loaded else None
        records = ledger_read(path)
        result = validate_chain(records, key=key)
        status = "CHAIN VALID" if result["valid"] else "CHAIN INVALID"
        print(f"[Oplogica] {status} | records={result['length']} "
              f"| signatures_checked={result['signatures_checked']}")
        for e in result["errors"]:
            print(f"  ERROR  record[{e['index']}] {e['code']}: {e['detail']}")
        for w in result["warnings"]:
            print(f"  WARN   record[{w['index']}] {w['code']}: {w['detail']}")
        return 0 if result["valid"] else 1
    print("usage: python oplogica_core.py verify <ledger.jsonl> [hmac_key_file]")
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
