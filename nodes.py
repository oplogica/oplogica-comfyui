"""Oplogica ComfyUI nodes (classic node API).

Ten functional nodes across six layers plus one utility. No decorative nodes:
every node performs a real operation and contributes fields to the sealed
decision record.
"""

from __future__ import annotations

import json
import uuid

try:
    from .oplogica_core import (
        SCHEMA_TASK, SCHEMA_EVIDENCE, SCHEMA_BUNDLE, SCHEMA_APPROVAL,
        GENESIS, utc_now_iso, age_days, hash_obj, sha256_hex, short_hash,
        merkle_root, evaluate_policy, seal_record, ledger_tail_hash,
        ledger_append, ledger_read, validate_chain, load_hmac_key,
        resolve_output_path,
    )
    from .oplogica_render import render_card, save_card
except ImportError:
    from oplogica_core import (
        SCHEMA_TASK, SCHEMA_EVIDENCE, SCHEMA_BUNDLE, SCHEMA_APPROVAL,
        GENESIS, utc_now_iso, age_days, hash_obj, sha256_hex, short_hash,
        merkle_root, evaluate_policy, seal_record, ledger_tail_hash,
        ledger_append, ledger_read, validate_chain, load_hmac_key,
        resolve_output_path,
    )
    from oplogica_render import render_card, save_card

try:
    import torch
except Exception:
    torch = None

CAT_INPUT = "Oplogica/1 Input"
CAT_EVIDENCE = "Oplogica/2 Evidence"
CAT_APPROVAL = "Oplogica/3 Approval"
CAT_VERIFY = "Oplogica/4 Verification"
CAT_TRUST = "Oplogica/5 Trust"
CAT_ACTION = "Oplogica/6 Action"
CAT_UTIL = "Oplogica/Utility"

DEFAULT_LEDGER = "oplogica/ledger.jsonl"

DEFAULT_POLICY = {
    "policy_id": "OPL-PAY-001",
    "version": "1.0.0",
    "allowed_actions": ["payment.vendor", "refund.customer"],
    "limits": {"max_amount": 5000, "currency": "USD"},
    "evidence": {"min_items": 2, "max_age_days": 90, "require_source": True},
    "sensitive_patterns": ["delete", "transfer.external", "credentials"],
    "required_approvals": 1,
}
DEFAULT_POLICY_JSON = json.dumps(DEFAULT_POLICY, indent=2)


# ===========================================================================
# Layer 1: INPUT
# ===========================================================================

class OplTaskInput:
    """Defines the proposed action under review. The semantic task hash is
    computed over actor, action, amount, currency, payload, and risk hint,
    deliberately excluding run identifiers, so approvals can bind to it."""

    CATEGORY = CAT_INPUT
    FUNCTION = "run"
    RETURN_TYPES = ("OPL_TASK", "STRING")
    RETURN_NAMES = ("task", "task_hash")

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "actor": ("STRING", {"default": "finops-agent-07"}),
            "actor_type": (["ai_agent", "human", "system"], {"default": "ai_agent"}),
            "action_type": ("STRING", {"default": "payment.vendor"}),
            "amount": ("FLOAT", {"default": 1840.00, "min": 0.0,
                                 "max": 1e12, "step": 0.01}),
            "currency": ("STRING", {"default": "USD"}),
            "payload_json": ("STRING", {
                "multiline": True,
                "default": '{"vendor": "Acme Cloud", "invoice": "INV-2291"}'}),
            "risk_hint": (["low", "medium", "high", "critical"],
                          {"default": "medium"}),
        }}

    def run(self, actor, actor_type, action_type, amount, currency,
            payload_json, risk_hint):
        try:
            payload = json.loads(payload_json) if payload_json.strip() else {}
        except json.JSONDecodeError as e:
            payload = {"_raw": payload_json, "_parse_error": str(e)}
        semantic = {
            "actor": actor.strip(),
            "actor_type": actor_type,
            "action_type": action_type.strip(),
            "amount": round(float(amount), 2),
            "currency": currency.strip().upper(),
            "payload": payload,
            "risk_hint": risk_hint,
        }
        task_hash = hash_obj(semantic)
        task = dict(semantic)
        task.update({
            "schema": SCHEMA_TASK,
            "task_id": str(uuid.uuid4()),
            "created_at": utc_now_iso(),
            "task_hash": task_hash,
        })
        print(f"[Oplogica] task {task['action_type']} "
              f"amount={task['amount']} hash={short_hash(task_hash)}")
        return (task, task_hash)


class OplEvidenceItem:
    """A single evidence item: a claim, its source reference, and the raw
    content. Content is hashed downstream at collection time; the raw content
    itself is never embedded in the sealed record, only its hash and a short
    excerpt."""

    CATEGORY = CAT_INPUT
    FUNCTION = "run"
    RETURN_TYPES = ("OPL_EVIDENCE",)
    RETURN_NAMES = ("evidence",)

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "claim": ("STRING", {"default": "Invoice INV-2291 issued for 1840.00 USD"}),
            "source_url": ("STRING", {"default": "https://billing.example.com/INV-2291"}),
            "content": ("STRING", {"multiline": True,
                                   "default": "Paste the verbatim source content here."}),
            "collected_at": ("STRING", {
                "default": "",
                "tooltip": "ISO 8601 UTC, e.g. 2026-06-10T14:00:00Z. Empty = now."}),
        }}

    def run(self, claim, source_url, content, collected_at):
        ts = collected_at.strip() or utc_now_iso()
        item = {
            "schema": SCHEMA_EVIDENCE,
            "claim": claim.strip(),
            "source": source_url.strip(),
            "content": content,
            "collected_at": ts,
        }
        return (item,)


# ===========================================================================
# Layer 2: EVIDENCE
# ===========================================================================

class OplEvidenceCollector:
    """Aggregates up to four evidence items into a bundle. Per item: SHA-256
    of content at ingestion, completeness flags, freshness in days, source
    presence. Deduplicates identical (content, claim) pairs, then builds a
    Merkle root over the SORTED item hashes: the root identifies the
    evidence set independent of input wiring order, and changes if any
    item's content, claim, source, or timestamp changes.

    MVP note: in the full catalog, completeness, freshness, reference
    integrity, and Merkle building are standalone nodes. The MVP folds them
    here to keep the demo graph at ten nodes."""

    CATEGORY = CAT_EVIDENCE
    FUNCTION = "run"
    RETURN_TYPES = ("OPL_BUNDLE", "STRING", "STRING")
    RETURN_NAMES = ("bundle", "merkle_root", "report")

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "evidence_1": ("OPL_EVIDENCE",),
                "max_age_days": ("INT", {"default": 90, "min": 0, "max": 36500}),
                "require_source": ("BOOLEAN", {"default": True}),
            },
            "optional": {
                "evidence_2": ("OPL_EVIDENCE",),
                "evidence_3": ("OPL_EVIDENCE",),
                "evidence_4": ("OPL_EVIDENCE",),
            },
        }

    def run(self, evidence_1, max_age_days, require_source,
            evidence_2=None, evidence_3=None, evidence_4=None):
        raw = [e for e in (evidence_1, evidence_2, evidence_3, evidence_4)
               if e is not None]
        seen = set()
        items = []
        duplicates = 0
        for raw_item in raw:
            content = raw_item.get("content", "")
            claim = raw_item.get("claim", "")
            content_hash = sha256_hex(content)
            key = (content_hash, claim)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            source = raw_item.get("source", "")
            a = age_days(raw_item.get("collected_at", ""))
            missing = []
            if not claim.strip():
                missing.append("claim")
            if not content.strip():
                missing.append("content")
            if require_source and not source.strip():
                missing.append("source")
            item = {
                "item_id": f"EV-{len(items) + 1:02d}",
                "claim": claim,
                "source": source,
                "content_sha256": content_hash,
                "content_chars": len(content),
                "excerpt": " ".join(content.split())[:96],
                "collected_at": raw_item.get("collected_at", ""),
                "age_days": a,
                "fresh": a is not None and a <= float(max_age_days),
                "complete": "claim" not in missing and "content" not in missing,
                "missing": missing,
            }
            item["item_hash"] = hash_obj({
                "claim": item["claim"], "source": item["source"],
                "content_sha256": item["content_sha256"],
                "collected_at": item["collected_at"]})
            items.append(item)

        stats = {
            "item_count": len(raw),
            "unique_count": len(items),
            "duplicates_removed": duplicates,
            "missing_source_count": sum(1 for i in items if "source" in i["missing"]),
            "incomplete_count": sum(1 for i in items if not i["complete"]),
            "stale_count": sum(1 for i in items if not i["fresh"]),
        }
        # Order normalization: leaf hashes are sorted lexicographically
        # before tree construction, so the root identifies the evidence SET.
        # Re-wiring the same items into different input slots does not change
        # the root and therefore does not invalidate a binding. Changing any
        # item's content, source, claim, or timestamp does change the root.
        root = merkle_root(sorted(i["item_hash"] for i in items))
        bundle = {
            "schema": SCHEMA_BUNDLE,
            "bundle_id": str(uuid.uuid4()),
            "created_at": utc_now_iso(),
            "items": items,
            "stats": stats,
            "merkle_root": root,
            "freshness_threshold_days": int(max_age_days),
        }
        lines = [f"EVIDENCE BUNDLE  {stats['unique_count']} unique item(s), "
                 f"{duplicates} duplicate(s) removed",
                 f"merkle_root: {root}"]
        for i in items:
            flag = "OK " if (i["complete"] and i["fresh"] and
                             "source" not in i["missing"]) else "WARN"
            lines.append(f"  [{flag}] {i['item_id']} "
                         f"{short_hash(i['item_hash'])} :: {i['claim'][:60]}")
        report = "\n".join(lines)
        print(f"[Oplogica] bundle {stats['unique_count']} items "
              f"root={short_hash(root)}")
        return (bundle, root, report)


# ===========================================================================
# Layer 4: VERIFICATION
# ===========================================================================

class OplPolicyCheck:
    """Deterministic policy verification: evaluates the task and its evidence
    bundle against a declarative JSON policy (allowed actions, monetary
    limits, evidence minimums, freshness, sensitive patterns). Outputs a
    structured result with one entry per rule, included verbatim in the
    sealed record."""

    CATEGORY = CAT_VERIFY
    FUNCTION = "run"
    RETURN_TYPES = ("OPL_CHECK", "BOOLEAN", "STRING")
    RETURN_NAMES = ("policy_result", "passed", "report")

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "task": ("OPL_TASK",),
            "bundle": ("OPL_BUNDLE",),
            "policy_json": ("STRING", {"multiline": True,
                                       "default": DEFAULT_POLICY_JSON}),
        }}

    def run(self, task, bundle, policy_json):
        try:
            policy = json.loads(policy_json)
        except json.JSONDecodeError as e:
            result = {
                "schema": "oplogica.policy_result.v1",
                "policy_id": "PARSE_ERROR",
                "policy_version": "0",
                "policy_hash": sha256_hex(policy_json),
                "checks": [{"rule": "policy_parse", "passed": False,
                            "detail": str(e), "enforced": True}],
                "passed": False,
                "requires_human": True,
                "evaluated_at": utc_now_iso(),
            }
            return (result, False, f"POLICY PARSE ERROR: {e}")

        result = evaluate_policy(policy, task, bundle)
        lines = [f"POLICY {result['policy_id']} v{result['policy_version']} "
                 f"hash={short_hash(result['policy_hash'])}"]
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            enforced = "" if c["enforced"] else " (informational)"
            lines.append(f"  [{mark}] {c['rule']}{enforced}: {c['detail']}")
        lines.append(f"OVERALL: {'PASSED' if result['passed'] else 'FAILED'}"
                     f"{' | human approval required' if result['requires_human'] else ''}")
        report = "\n".join(lines)
        print(f"[Oplogica] policy {result['policy_id']} "
              f"passed={result['passed']}")
        return (result, result["passed"], report)


# ===========================================================================
# Layer 3: APPROVAL
# ===========================================================================

class OplHumanApprovalGate:
    """Records an explicit human decision and binds it to exactly what was
    reviewed: BOTH the semantic task hash AND the evidence Merkle root are
    enforced in strict mode, not merely recorded.

    Strict binding flow (recommended, the demo default): run once with
    decision PENDING, copy the task hash and the evidence root from the gate
    report, paste them into strict_expected_task_hash and
    strict_expected_evidence_root, set decision to APPROVED, enter your
    identity, run again. If the task changed after review the approval is
    downgraded with TASK_BINDING_MISMATCH; if the evidence changed,
    EVIDENCE_BINDING_MISMATCH; if both changed, APPROVAL_BINDING_MISMATCH.
    An APPROVED decision with an empty approver identity is downgraded with
    NO_APPROVER_IDENTITY. An approval never silently transfers to a task or
    an evidence bundle the human did not review.

    Open mode (both strict fields empty) records the bound hashes without
    enforcing an expected value at the gate; the Decision Sealer still
    verifies the bound hashes against the task and bundle it actually seals.

    ComfyUI does not natively pause execution mid-graph; this two-pass,
    hash-bound design is the honest equivalent, and the approval state is
    itself a recorded, sealed artifact. A blocking in-graph gate is a Phase 2
    item (see README)."""

    CATEGORY = CAT_APPROVAL
    FUNCTION = "run"
    RETURN_TYPES = ("OPL_APPROVAL", "BOOLEAN", "STRING")
    RETURN_NAMES = ("approval", "approved", "report")

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "task": ("OPL_TASK",),
                "bundle": ("OPL_BUNDLE",),
                "decision": (["PENDING", "APPROVED", "REJECTED"],
                             {"default": "PENDING"}),
                "approver": ("STRING", {"default": ""}),
                "note": ("STRING", {"multiline": True, "default": ""}),
                "strict_expected_task_hash": ("STRING", {
                    "default": "",
                    "tooltip": "Paste the task hash you reviewed (printed by "
                               "the PENDING pass). Empty = not enforced at "
                               "the gate."}),
                "strict_expected_evidence_root": ("STRING", {
                    "default": "",
                    "tooltip": "Paste the evidence Merkle root you reviewed "
                               "(printed by the PENDING pass). Empty = not "
                               "enforced at the gate."}),
            },
        }

    def run(self, task, bundle, decision, approver, note,
            strict_expected_task_hash, strict_expected_evidence_root):
        current_task_hash = task.get("task_hash", "")
        current_evidence_root = bundle.get("merkle_root", "")
        expected_task = strict_expected_task_hash.strip()
        expected_evid = strict_expected_evidence_root.strip()

        task_binding_ok = (not expected_task) or (expected_task == current_task_hash)
        evidence_binding_ok = (not expected_evid) or (expected_evid == current_evidence_root)
        binding_ok = task_binding_ok and evidence_binding_ok

        if expected_task and expected_evid:
            binding_mode = "strict"
        elif expected_task:
            binding_mode = "strict_task_only"
        elif expected_evid:
            binding_mode = "strict_evidence_only"
        else:
            binding_mode = "open"

        effective = decision
        downgrade_reason = None
        if decision == "APPROVED":
            if not task_binding_ok and not evidence_binding_ok:
                effective = "PENDING"
                downgrade_reason = ("APPROVAL_BINDING_MISMATCH: task and "
                                    "evidence changed after review")
            elif not task_binding_ok:
                effective = "PENDING"
                downgrade_reason = ("TASK_BINDING_MISMATCH: task changed "
                                    "after review")
            elif not evidence_binding_ok:
                effective = "PENDING"
                downgrade_reason = ("EVIDENCE_BINDING_MISMATCH: evidence "
                                    "changed after review")
            elif not approver.strip():
                effective = "PENDING"
                downgrade_reason = ("NO_APPROVER_IDENTITY: an approval "
                                    "without an identity is not an approval")

        approval = {
            "schema": SCHEMA_APPROVAL,
            "gate": "human_approval_gate.v2",
            "decision": decision,
            "effective_decision": effective,
            "downgrade_reason": downgrade_reason,
            "approver": approver.strip(),
            "note": note.strip(),
            "approved_at": utc_now_iso() if decision != "PENDING" else None,
            "bound_task_hash": current_task_hash,
            "bound_evidence_root": current_evidence_root,
            "current_task_hash": current_task_hash,
            "current_evidence_root": current_evidence_root,
            "expected_task_hash": expected_task or None,
            "expected_evidence_root": expected_evid or None,
            "binding_mode": binding_mode,
            "task_binding_ok": task_binding_ok,
            "evidence_binding_ok": evidence_binding_ok,
            "binding_ok": binding_ok,
        }
        approved = effective == "APPROVED"
        lines = [
            f"HUMAN APPROVAL GATE  effective={effective}",
            f"approver: {approver.strip() or '(none)'}",
            f"binding_mode: {binding_mode}",
            "current task_hash (copy for strict mode):",
            current_task_hash,
            "current evidence_root (copy for strict mode):",
            current_evidence_root,
        ]
        if expected_task:
            lines.append(f"expected task_hash: {expected_task}")
            lines.append(f"task binding: {'ok' if task_binding_ok else 'MISMATCH'}")
        if expected_evid:
            lines.append(f"expected evidence_root: {expected_evid}")
            lines.append(f"evidence binding: "
                         f"{'ok' if evidence_binding_ok else 'MISMATCH'}")
        if binding_mode == "open" and decision == "APPROVED":
            lines.append("note: open mode records the bound hashes but does "
                         "not enforce expected values at the gate; strict "
                         "mode is recommended for real reviews")
        if downgrade_reason:
            lines.append(f"DOWNGRADED: {downgrade_reason}")
        report = "\n".join(lines)
        print(f"[Oplogica] approval effective={effective} "
              f"by='{approver.strip()}' mode={binding_mode} "
              f"task_ok={task_binding_ok} evidence_ok={evidence_binding_ok}")
        return (approval, approved, report)


# ===========================================================================
# Layer 5: TRUST
# ===========================================================================

class OplDecisionSealer:
    """Computes the verdict and seals the decision record.

    Verdict logic: APPROVED only when ALL of the following hold: the policy
    passed, the effective human decision is APPROVED, the approval's bound
    task hash matches the sealed task, the approval's bound evidence Merkle
    root matches the sealed bundle, and an approver identity exists.
    Anything else is BLOCKED with explicit reason codes. Every run produces
    a sealed record either way: blocking generates evidence rather than
    silence.

    Sealing: canonical JSON, SHA-256 record hash over everything except the
    integrity block, previous-record hash read from the ledger tail for
    chaining, optional HMAC-SHA256 signature from a local key file.

    Chain state is never cached: IS_CHANGED forces this node to re-execute
    on every queue, so the previous-record hash is read from the ledger
    file as it exists at run time. Renaming, deleting, or replacing the
    ledger between queues yields a fresh chain start (GENESIS) instead of
    a stale in-memory tail."""

    CATEGORY = CAT_TRUST
    FUNCTION = "run"
    RETURN_TYPES = ("OPL_RECORD", "STRING", "STRING", "STRING")
    RETURN_NAMES = ("record", "verdict", "record_hash", "record_json")

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        # The sealed record depends on external mutable state (the ledger
        # tail on disk). NaN never compares equal to itself, which is the
        # ComfyUI idiom for "always re-execute"; without this, ComfyUI's
        # output cache can replay a record whose prev hash predates a
        # ledger rename, delete, or replacement.
        return float("nan")

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "task": ("OPL_TASK",),
            "bundle": ("OPL_BUNDLE",),
            "policy_result": ("OPL_CHECK",),
            "approval": ("OPL_APPROVAL",),
            "ledger_path": ("STRING", {"default": DEFAULT_LEDGER}),
            "hmac_key_path": ("STRING", {
                "default": "",
                "tooltip": "Path to a key file (>=16 bytes). Empty = unsigned."}),
        }}

    def run(self, task, bundle, policy_result, approval,
            ledger_path, hmac_key_path):
        reasons = []
        if not policy_result.get("passed", False):
            failed = [c["rule"] for c in policy_result.get("checks", [])
                      if c.get("enforced") and not c.get("passed")]
            reasons.append("POLICY_FAILED:" + ",".join(failed))
        eff = approval.get("effective_decision", "PENDING")
        if eff == "REJECTED":
            reasons.append("APPROVAL_REJECTED")
        elif eff == "PENDING":
            code = ("APPROVAL_PENDING" if not approval.get("downgrade_reason")
                    else approval["downgrade_reason"].split(":")[0])
            reasons.append(code)
        elif eff == "APPROVED":
            # Seal-time binding verification: the approval must be bound to
            # exactly the task and the evidence bundle being sealed. This
            # catches a different task or a different bundle wired into the
            # sealer than the one the gate saw, independent of gate mode.
            task_match = approval.get("bound_task_hash") == task.get("task_hash")
            evid_match = (approval.get("bound_evidence_root")
                          == bundle.get("merkle_root"))
            if not task_match and not evid_match:
                reasons.append("APPROVAL_BINDING_MISMATCH")
            elif not task_match:
                reasons.append("TASK_BINDING_MISMATCH")
            elif not evid_match:
                reasons.append("EVIDENCE_BINDING_MISMATCH")
            if not approval.get("approver", "").strip():
                reasons.append("NO_APPROVER_IDENTITY")

        status = "APPROVED" if not reasons else "BLOCKED"
        verdict = {
            "status": status,
            "reasons": reasons,
            "requires_human": policy_result.get("requires_human", True),
        }

        evidence_summary = {
            "merkle_root": bundle.get("merkle_root"),
            "stats": bundle.get("stats", {}),
            "items": [{k: v for k, v in item.items() if k != "content"}
                      for item in bundle.get("items", [])],
        }

        resolved = resolve_output_path(ledger_path)
        prev = ledger_tail_hash(resolved)
        signer = load_hmac_key(hmac_key_path) if hmac_key_path.strip() else None

        record = seal_record(
            task={k: v for k, v in task.items()},
            evidence_summary=evidence_summary,
            checks={"policy": policy_result},
            approvals=[approval],
            verdict=verdict,
            prev_hash=prev,
            signer=signer,
        )
        rh = record["integrity"]["record_hash"]
        print(f"[Oplogica] sealed {status} record={short_hash(rh)} "
              f"prev={short_hash(prev)} signed={signer is not None}")
        return (record, status, rh, json.dumps(record, indent=2,
                                               ensure_ascii=False))


class OplChainValidator:
    """Re-reads the ledger and validates the entire chain: recomputes every
    record hash, verifies every prev-hash link, and checks HMAC signatures
    when a key is provided. The optional run_after input exists purely to
    force execution ordering after the ledger writer in the same graph."""

    CATEGORY = CAT_TRUST
    FUNCTION = "run"
    RETURN_TYPES = ("BOOLEAN", "STRING", "INT")
    RETURN_NAMES = ("valid", "report", "length")
    OUTPUT_NODE = True

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "ledger_path": ("STRING", {"default": DEFAULT_LEDGER}),
                "hmac_key_path": ("STRING", {"default": ""}),
            },
            "optional": {
                "run_after": ("STRING", {"forceInput": True}),
            },
        }

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        return float("nan")  # the ledger lives outside the graph: always re-run

    def run(self, ledger_path, hmac_key_path, run_after=None):
        resolved = resolve_output_path(ledger_path)
        records = ledger_read(resolved)
        key = None
        if hmac_key_path.strip():
            loaded = load_hmac_key(hmac_key_path)
            key = loaded[0] if loaded else None
        result = validate_chain(records, key=key)
        status = "CHAIN VALID" if result["valid"] else "CHAIN INVALID"
        lines = [f"{status}  records={result['length']} "
                 f"signatures_checked={result['signatures_checked']}",
                 f"ledger: {resolved}"]
        for e in result["errors"]:
            lines.append(f"  ERROR record[{e['index']}] {e['code']}: {e['detail']}")
        for w in result["warnings"]:
            lines.append(f"  WARN  record[{w['index']}] {w['code']}: {w['detail']}")
        report = "\n".join(lines)
        print(f"[Oplogica] {status} ({result['length']} records)")
        return (result["valid"], report, result["length"])


# ===========================================================================
# Layer 6: ACTION
# ===========================================================================

class OplAuditLedgerWriter:
    """Appends the sealed record to the append-only JSONL ledger. Idempotent
    against immediate duplicates: re-queueing an unchanged graph does not
    create a second copy of the same record. Appends are verified against
    the file as it exists at write time: a record whose prev hash no longer
    matches the actual tail (ledger renamed, deleted, replaced, or
    truncated since sealing) is rejected with STALE_PREV_REJECTED instead
    of planting a chain break. MVP scope is deliberate: this extension
    records and gates decisions; it does not execute external side
    effects. The Guarded Executor with webhook support is a Phase 2 node."""

    CATEGORY = CAT_ACTION
    FUNCTION = "run"
    RETURN_TYPES = ("STRING", "INT", "STRING", "STRING")
    RETURN_NAMES = ("ledger_path", "position", "record_hash", "status")
    OUTPUT_NODE = True

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "record": ("OPL_RECORD",),
            "ledger_path": ("STRING", {"default": DEFAULT_LEDGER}),
        }}

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        return float("nan")

    def run(self, record, ledger_path):
        resolved = resolve_output_path(ledger_path)
        position, status = ledger_append(resolved, record)
        rh = record.get("integrity", {}).get("record_hash", "")
        if status == "STALE_PREV_REJECTED":
            print(f"[Oplogica] ledger {status}: the record's prev hash no "
                  f"longer matches the ledger at {resolved} (file renamed, "
                  f"deleted, replaced, or truncated since sealing). Nothing "
                  f"was written. Queue the workflow again to re-seal "
                  f"against the current file state.")
        else:
            print(f"[Oplogica] ledger {status} pos={position} "
                  f"record={short_hash(rh)} -> {resolved}")
        return (resolved, position, rh, status)


class OplDecisionCardRenderer:
    """Renders the sealed record as a dark-theme decision card image
    (default 1200x675, LinkedIn-native). The card displays the verdict,
    task, evidence Merkle root, policy result, bound approval, chain hashes,
    and the scope line 'Integrity is not truth'. Output is a standard
    ComfyUI IMAGE; wire it to a Preview Image or Save Image node."""

    CATEGORY = CAT_ACTION
    FUNCTION = "run"
    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("image",)

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "record": ("OPL_RECORD",),
            "width": ("INT", {"default": 1200, "min": 600, "max": 4096}),
            "height": ("INT", {"default": 675, "min": 338, "max": 4096}),
            "save_png": ("BOOLEAN", {"default": True}),
            "filename_prefix": ("STRING", {"default": "oplogica_card"}),
        }}

    def run(self, record, width, height, save_png, filename_prefix):
        img = render_card(record, width, height)
        if save_png:
            out_dir = resolve_output_path("oplogica")
            path = save_card(record, out_dir, filename_prefix, width, height)
            print(f"[Oplogica] card saved -> {path}")
        import numpy as np
        arr = np.asarray(img.convert("RGB")).astype("float32") / 255.0
        if torch is not None:
            return (torch.from_numpy(arr)[None,],)
        return (arr[None,],)  # standalone test path, outside ComfyUI


# ===========================================================================
# Utility
# ===========================================================================

class OplTextDisplay:
    """Displays any STRING output inside the node (gate reports, record JSON,
    validator reports). The in-node display requires the bundled JS extension;
    if a future frontend version breaks it, the value is still printed to the
    server console and embedded in the sealed record, so nothing is lost."""

    CATEGORY = CAT_UTIL
    FUNCTION = "run"
    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    OUTPUT_NODE = True

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {
            "text": ("STRING", {"forceInput": True}),
        }}

    def run(self, text):
        print(f"[Oplogica] display:\n{text}")
        return {"ui": {"text": [text]}, "result": (text,)}


# ===========================================================================
# Registration
# ===========================================================================

NODE_CLASS_MAPPINGS = {
    "OplTaskInput": OplTaskInput,
    "OplEvidenceItem": OplEvidenceItem,
    "OplEvidenceCollector": OplEvidenceCollector,
    "OplPolicyCheck": OplPolicyCheck,
    "OplHumanApprovalGate": OplHumanApprovalGate,
    "OplDecisionSealer": OplDecisionSealer,
    "OplChainValidator": OplChainValidator,
    "OplAuditLedgerWriter": OplAuditLedgerWriter,
    "OplDecisionCardRenderer": OplDecisionCardRenderer,
    "OplTextDisplay": OplTextDisplay,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "OplTaskInput": "Oplogica · Task Input",
    "OplEvidenceItem": "Oplogica · Evidence Item",
    "OplEvidenceCollector": "Oplogica · Evidence Collector",
    "OplPolicyCheck": "Oplogica · Policy Verification",
    "OplHumanApprovalGate": "Oplogica · Human Approval Gate",
    "OplDecisionSealer": "Oplogica · Decision Sealer",
    "OplChainValidator": "Oplogica · Chain Validator",
    "OplAuditLedgerWriter": "Oplogica · Audit Ledger Writer",
    "OplDecisionCardRenderer": "Oplogica · Decision Card Renderer",
    "OplTextDisplay": "Oplogica · Text Display",
}
