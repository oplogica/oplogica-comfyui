#!/usr/bin/env python3
"""
Oplogica ComfyUI extension test suite (pack version 1.0.0).

Runs with pytest (pytest tests/ -q) or standalone
(python3 tests/test_oplogica.py). Every test uses plain asserts; the
standalone runner collects all test_* functions, executes them, and reports
PASS/FAIL with a nonzero exit on failure.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import oplogica_core as core  # noqa: E402
import nodes as opl_nodes  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers: build real objects by running the actual nodes
# ---------------------------------------------------------------------------

def make_task(action="payment.vendor", amount=1840.00, actor="finops-agent-07"):
    node = opl_nodes.OplTaskInput()
    task, task_hash = node.run(
        actor=actor, actor_type="ai_agent", action_type=action,
        amount=amount, currency="USD",
        payload_json='{"vendor": "Acme Cloud", "invoice": "INV-2291"}',
        risk_hint="medium")
    return task, task_hash


def make_evidence(claim="Invoice INV-2291 issued", source="https://x.example/1",
                  content="invoice content body", collected_at=""):
    node = opl_nodes.OplEvidenceItem()
    (item,) = node.run(claim=claim, source_url=source, content=content,
                       collected_at=collected_at)
    return item


def make_bundle(items=None, max_age_days=90, require_source=True):
    if items is None:
        items = [
            make_evidence(claim="claim one", content="content one"),
            make_evidence(claim="claim two", content="content two",
                          source="https://x.example/2"),
        ]
    node = opl_nodes.OplEvidenceCollector()
    kwargs = {"max_age_days": max_age_days, "require_source": require_source}
    for i, item in enumerate(items[:4], start=1):
        kwargs["evidence_%d" % i] = item
    bundle, root, report = node.run(**kwargs)
    return bundle, root, report


def make_policy_result(task, bundle, policy=None):
    policy = policy or dict(opl_nodes.DEFAULT_POLICY)
    return core.evaluate_policy(policy, task, bundle)


def make_approval(task, bundle, decision="APPROVED", approver="m.ibrahim",
                  strict_task="", strict_evid="", note=""):
    node = opl_nodes.OplHumanApprovalGate()
    approval, approved, report = node.run(
        task=task, bundle=bundle, decision=decision, approver=approver,
        note=note, strict_expected_task_hash=strict_task,
        strict_expected_evidence_root=strict_evid)
    return approval, approved, report


def seal(task, bundle, policy_result, approval, ledger_path, key_path=""):
    node = opl_nodes.OplDecisionSealer()
    return node.run(task=task, bundle=bundle, policy_result=policy_result,
                    approval=approval, ledger_path=ledger_path,
                    hmac_key_path=key_path)


def full_run(ledger, amount=1840.00, decision="APPROVED",
             approver="m.ibrahim", strict=True):
    """Run task -> bundle -> policy -> gate -> sealer with optional strict
    dual binding against the current task hash and evidence root."""
    task, th = make_task(amount=amount)
    bundle, root, _ = make_bundle()
    pol = make_policy_result(task, bundle)
    appr, _, _ = make_approval(
        task, bundle, decision=decision, approver=approver,
        strict_task=th if strict else "", strict_evid=root if strict else "")
    record, verdict, rh, record_json = seal(task, bundle, pol, appr, ledger)
    return record, verdict, rh, record_json


# ---------------------------------------------------------------------------
# Core: canonical JSON and hashing
# ---------------------------------------------------------------------------

def test_canonical_json_key_order_independent():
    a = core.canonical_json({"b": 1, "a": [2, {"d": 3, "c": 4}]})
    b = core.canonical_json({"a": [2, {"c": 4, "d": 3}], "b": 1})
    assert a == b


def test_hash_obj_stable_and_sensitive():
    obj = {"x": 1, "y": "z"}
    h1 = core.hash_obj(obj)
    h2 = core.hash_obj({"y": "z", "x": 1})
    assert h1 == h2
    assert len(h1) == 64
    assert core.hash_obj({"x": 2, "y": "z"}) != h1


# ---------------------------------------------------------------------------
# Core: Merkle tree
# ---------------------------------------------------------------------------

def test_merkle_empty_sentinel():
    assert core.merkle_root([]) == core.sha256_hex(b"OPLOGICA_EMPTY_BUNDLE")


def test_merkle_single_leaf_is_root():
    leaf = core.sha256_hex(b"leaf")
    assert core.merkle_root([leaf]) == leaf


def test_merkle_pair_and_odd_padding():
    l1, l2, l3 = (core.sha256_hex(x) for x in (b"a", b"b", b"c"))
    pair = core.merkle_root([l1, l2])
    assert pair == core.sha256_hex(l1 + l2)
    odd = core.merkle_root([l1, l2, l3])
    expected = core.sha256_hex(core.sha256_hex(l1 + l2) +
                               core.sha256_hex(l3 + l3))
    assert odd == expected


def test_merkle_tamper_changes_root():
    l1, l2 = core.sha256_hex(b"a"), core.sha256_hex(b"b")
    l2_tampered = core.sha256_hex(b"B")
    assert core.merkle_root([l1, l2]) != core.merkle_root([l1, l2_tampered])
    # The generic tree itself is order-sensitive; order normalization is the
    # Evidence Collector's responsibility (tested separately below).
    assert core.merkle_root([l1, l2]) != core.merkle_root([l2, l1])


# ---------------------------------------------------------------------------
# Core: HMAC
# ---------------------------------------------------------------------------

def test_hmac_sign_and_verify():
    key = b"0123456789abcdef0123456789abcdef"
    sig = core.hmac_sign("deadbeef", key, "kid-1")
    assert sig["alg"] == "HMAC-SHA256"
    assert core.hmac_verify("deadbeef", sig, key)


def test_hmac_wrong_key_fails():
    key = b"0123456789abcdef0123456789abcdef"
    other = b"ffffffffffffffffffffffffffffffff"
    sig = core.hmac_sign("deadbeef", key, "kid-1")
    assert not core.hmac_verify("deadbeef", sig, other)
    assert not core.hmac_verify("deadbeee", sig, key)


def test_hmac_key_loading_and_min_length():
    with tempfile.TemporaryDirectory() as td:
        short = os.path.join(td, "short.key")
        with open(short, "wb") as f:
            f.write(b"tiny")
        try:
            core.load_hmac_key(short)
            raised = False
        except ValueError:
            raised = True
        assert raised, "keys under 16 bytes must be rejected"

        good = os.path.join(td, "good.key")
        with open(good, "wb") as f:
            f.write(b"0123456789abcdef0123456789abcdef")
        key, key_id = core.load_hmac_key(good)
        assert len(key) == 32 and len(key_id) == 12


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

def test_policy_pass_on_valid_payment():
    task, _ = make_task()
    bundle, _, _ = make_bundle()
    result = make_policy_result(task, bundle)
    assert result["passed"] is True
    assert result["requires_human"] is True  # required_approvals >= 1


def test_policy_blocks_over_limit():
    task, _ = make_task(amount=8200.00)
    bundle, _, _ = make_bundle()
    result = make_policy_result(task, bundle)
    assert result["passed"] is False
    failed = [c["rule"] for c in result["checks"] if not c["passed"]]
    assert "amount_within_limit" in failed


def test_policy_blocks_disallowed_action():
    task, _ = make_task(action="transfer.external.wire")
    bundle, _, _ = make_bundle()
    result = make_policy_result(task, bundle)
    assert result["passed"] is False
    failed = [c["rule"] for c in result["checks"] if not c["passed"]]
    assert "action_allowed" in failed


def test_policy_blocks_insufficient_evidence():
    task, _ = make_task()
    bundle, _, _ = make_bundle(items=[make_evidence()])  # 1 < min_items 2
    result = make_policy_result(task, bundle)
    assert result["passed"] is False
    failed = [c["rule"] for c in result["checks"] if not c["passed"]]
    assert "evidence_min_items" in failed


def test_policy_sensitive_pattern_flags_human():
    policy = json.loads(json.dumps(dict(opl_nodes.DEFAULT_POLICY)))
    policy["allowed_actions"].append("delete.record")
    policy["required_approvals"] = 0
    task, _ = make_task(action="delete.record")
    bundle, _, _ = make_bundle()
    result = core.evaluate_policy(policy, task, bundle)
    scan = [c for c in result["checks"] if c["rule"] == "sensitive_action_scan"]
    assert scan and scan[0]["enforced"] is False
    assert result["requires_human"] is True  # pattern hit overrides 0 approvals
    assert result["passed"] is True  # informational rule never blocks alone


# ---------------------------------------------------------------------------
# Human Approval Gate: decisions and identity
# ---------------------------------------------------------------------------

def test_gate_pending_is_not_approved():
    task, _ = make_task()
    bundle, _, _ = make_bundle()
    approval, approved, _ = make_approval(task, bundle, decision="PENDING",
                                          approver="")
    assert approved is False
    assert approval["effective_decision"] == "PENDING"
    assert approval["approved_at"] is None
    assert approval["downgrade_reason"] is None


def test_gate_rejected():
    task, _ = make_task()
    bundle, _, _ = make_bundle()
    approval, approved, _ = make_approval(task, bundle, decision="REJECTED")
    assert approved is False
    assert approval["effective_decision"] == "REJECTED"


def test_gate_no_identity_downgrades_even_with_matching_bindings():
    task, th = make_task()
    bundle, root, _ = make_bundle()
    approval, approved, _ = make_approval(task, bundle, approver="   ",
                                          strict_task=th, strict_evid=root)
    assert approved is False
    assert approval["effective_decision"] == "PENDING"
    assert approval["downgrade_reason"].startswith("NO_APPROVER_IDENTITY")
    assert approval["task_binding_ok"] and approval["evidence_binding_ok"]


# ---------------------------------------------------------------------------
# Human Approval Gate: dual strict binding
# ---------------------------------------------------------------------------

def test_gate_strict_dual_binding_approves_when_unchanged():
    task, th = make_task()
    bundle, root, _ = make_bundle()
    approval, approved, report = make_approval(task, bundle,
                                               strict_task=th,
                                               strict_evid=root)
    assert approved is True
    assert approval["binding_mode"] == "strict"
    assert approval["binding_ok"] is True
    assert approval["bound_task_hash"] == th
    assert approval["bound_evidence_root"] == root
    assert approval["current_task_hash"] == th
    assert approval["current_evidence_root"] == root
    assert approval["expected_task_hash"] == th
    assert approval["expected_evidence_root"] == root
    # Report must let a reviewer copy both values.
    assert th in report and root in report


def test_gate_task_binding_mismatch():
    task, _ = make_task(amount=9999.00)  # the task changed after review
    bundle, root, _ = make_bundle()
    reviewed_task_hash = core.hash_obj({"reviewed": "earlier"})
    approval, approved, _ = make_approval(task, bundle,
                                          strict_task=reviewed_task_hash,
                                          strict_evid=root)
    assert approved is False
    assert approval["effective_decision"] == "PENDING"
    assert approval["downgrade_reason"].startswith("TASK_BINDING_MISMATCH")
    assert approval["task_binding_ok"] is False
    assert approval["evidence_binding_ok"] is True


def test_gate_evidence_binding_mismatch():
    task, th = make_task()
    bundle, _, _ = make_bundle()
    reviewed_root = core.hash_obj({"reviewed": "earlier evidence"})
    approval, approved, _ = make_approval(task, bundle, strict_task=th,
                                          strict_evid=reviewed_root)
    assert approved is False
    assert approval["effective_decision"] == "PENDING"
    assert approval["downgrade_reason"].startswith(
        "EVIDENCE_BINDING_MISMATCH")
    assert approval["task_binding_ok"] is True
    assert approval["evidence_binding_ok"] is False


def test_gate_combined_binding_mismatch():
    task, _ = make_task(amount=9999.00)
    bundle, _, _ = make_bundle()
    approval, approved, _ = make_approval(
        task, bundle,
        strict_task=core.hash_obj({"old": "task"}),
        strict_evid=core.hash_obj({"old": "evidence"}))
    assert approved is False
    assert approval["effective_decision"] == "PENDING"
    assert approval["downgrade_reason"].startswith(
        "APPROVAL_BINDING_MISMATCH")
    assert approval["task_binding_ok"] is False
    assert approval["evidence_binding_ok"] is False


def test_gate_binding_modes_reported():
    task, th = make_task()
    bundle, root, _ = make_bundle()
    a1, _, _ = make_approval(task, bundle)
    assert a1["binding_mode"] == "open"
    a2, _, _ = make_approval(task, bundle, strict_task=th)
    assert a2["binding_mode"] == "strict_task_only"
    a3, _, _ = make_approval(task, bundle, strict_evid=root)
    assert a3["binding_mode"] == "strict_evidence_only"
    a4, _, _ = make_approval(task, bundle, strict_task=th, strict_evid=root)
    assert a4["binding_mode"] == "strict"


# ---------------------------------------------------------------------------
# Adversarial: evidence changes after the human reviewed it
# ---------------------------------------------------------------------------

def test_adversarial_evidence_changed_after_review_is_blocked():
    """A human approves task hash A and evidence root R1. The task remains
    unchanged, but the evidence content changes, producing root R2. The
    system must not approve: BLOCKED / EVIDENCE_BINDING_MISMATCH."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()

        # Pass 1: the reviewer sees this evidence and records its root R1.
        reviewed_bundle, r1, _ = make_bundle(items=[
            make_evidence(claim="invoice", content="Status: open."),
            make_evidence(claim="contract", content="active through 2026",
                          source="https://x.example/2"),
        ])

        # After review: the evidence content is changed (R2).
        changed_bundle, r2, _ = make_bundle(items=[
            make_evidence(claim="invoice", content="Status: VOID."),
            make_evidence(claim="contract", content="active through 2026",
                          source="https://x.example/2"),
        ])
        assert r1 != r2  # content change must change the Merkle root

        # Pass 2: APPROVED with the values copied during review (A, R1),
        # but the graph now carries the changed bundle.
        pol = make_policy_result(task, changed_bundle)
        appr, approved, _ = make_approval(task, changed_bundle,
                                          strict_task=th, strict_evid=r1)
        assert approved is False
        record, verdict, _, _ = seal(task, changed_bundle, pol, appr, ledger)
        assert verdict == "BLOCKED"
        assert "EVIDENCE_BINDING_MISMATCH" in record["verdict"]["reasons"]


def test_adversarial_task_changed_after_review_is_blocked():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        reviewed_task, reviewed_th = make_task(amount=1840.00)
        bundle, root, _ = make_bundle()
        # After review, the task amount is changed.
        changed_task, changed_th = make_task(amount=9999.00)
        assert reviewed_th != changed_th
        pol = make_policy_result(changed_task, bundle)
        appr, approved, _ = make_approval(changed_task, bundle,
                                          strict_task=reviewed_th,
                                          strict_evid=root)
        assert approved is False
        record, verdict, _, _ = seal(changed_task, bundle, pol, appr, ledger)
        assert verdict == "BLOCKED"
        assert "TASK_BINDING_MISMATCH" in record["verdict"]["reasons"]


def test_adversarial_task_and_evidence_changed_is_blocked():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, _ = make_task(amount=9999.00)
        bundle, _, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        appr, approved, _ = make_approval(
            task, bundle,
            strict_task=core.hash_obj({"reviewed": "task"}),
            strict_evid=core.hash_obj({"reviewed": "evidence"}))
        assert approved is False
        record, verdict, _, _ = seal(task, bundle, pol, appr, ledger)
        assert verdict == "BLOCKED"
        assert "APPROVAL_BINDING_MISMATCH" in record["verdict"]["reasons"]


# ---------------------------------------------------------------------------
# Decision Sealer: verdicts, reason codes, record contents
# ---------------------------------------------------------------------------

def test_sealer_approved_path_and_hash_stability():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()
        secret_tail = "CONFIDENTIAL-TAIL-MARKER-9F2A"
        long_content = ("x" * 200) + secret_tail  # beyond the 96-char excerpt
        bundle, root, _ = make_bundle(items=[
            make_evidence(claim="long doc", content=long_content),
            make_evidence(claim="claim two", content="content two",
                          source="https://x.example/2"),
        ])
        pol = make_policy_result(task, bundle)
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        record, verdict, rh, record_json = seal(task, bundle, pol, appr,
                                                ledger)
        assert verdict == "APPROVED"
        assert record["verdict"]["reasons"] == []
        assert record["chain"]["prev_record_hash"] == core.GENESIS
        assert core.compute_record_hash(record) == rh
        assert json.loads(record_json)["integrity"]["record_hash"] == rh
        # Raw evidence content never enters the sealed record: only its
        # SHA-256 and a 96-char excerpt. The tail must be absent.
        assert secret_tail not in record_json
        assert core.sha256_hex(long_content) in record_json


def test_sealed_record_contains_binding_fields():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record, verdict, _, _ = full_run(ledger)
        assert verdict == "APPROVED"
        ap = record["approvals"][0]
        task_hash = record["task"]["task_hash"]
        evid_root = record["evidence"]["merkle_root"]
        assert ap["bound_task_hash"] == task_hash
        assert ap["bound_evidence_root"] == evid_root
        assert ap["current_task_hash"] == task_hash
        assert ap["current_evidence_root"] == evid_root
        assert ap["binding_mode"] == "strict"
        assert ap["effective_decision"] == "APPROVED"
        assert ap["downgrade_reason"] is None
        assert ap["schema"] == "oplogica.approval.v2"


def test_sealer_blocked_on_policy_failure():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record, verdict, _, _ = full_run(ledger, amount=8200.00)
        assert verdict == "BLOCKED"
        assert any(r.startswith("POLICY_FAILED") for r in
                   record["verdict"]["reasons"])


def test_sealer_blocked_on_pending_approval():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record, verdict, _, _ = full_run(ledger, decision="PENDING",
                                         approver="", strict=False)
        assert verdict == "BLOCKED"
        assert "APPROVAL_PENDING" in record["verdict"]["reasons"]


def test_sealer_blocked_on_rejection():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record, verdict, _, _ = full_run(ledger, decision="REJECTED")
        assert verdict == "BLOCKED"
        assert "APPROVAL_REJECTED" in record["verdict"]["reasons"]


def test_sealer_blocked_on_missing_identity():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record, verdict, _, _ = full_run(ledger, approver="")
        assert verdict == "BLOCKED"
        # Gate downgraded APPROVED to PENDING with the identity code.
        assert "NO_APPROVER_IDENTITY" in record["verdict"]["reasons"]


def test_sealer_seal_time_bundle_swap_is_blocked():
    """The gate approved bundle A; a different bundle B is wired into the
    sealer. The seal-time check must block, independent of gate mode."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()
        bundle_a, root_a, _ = make_bundle()
        bundle_b, root_b, _ = make_bundle(items=[
            make_evidence(claim="other", content="other content",
                          source="https://x.example/9"),
            make_evidence(claim="more", content="more content",
                          source="https://x.example/10"),
        ])
        assert root_a != root_b
        pol = make_policy_result(task, bundle_b)
        appr, approved, _ = make_approval(task, bundle_a, strict_task=th,
                                          strict_evid=root_a)
        assert approved is True  # the gate itself saw consistent values
        record, verdict, _, _ = seal(task, bundle_b, pol, appr, ledger)
        assert verdict == "BLOCKED"
        assert "EVIDENCE_BINDING_MISMATCH" in record["verdict"]["reasons"]


def test_sealer_seal_time_task_swap_is_blocked():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task_a, th_a = make_task(amount=1840.00)
        task_b, th_b = make_task(amount=2000.00)
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task_b, bundle)
        appr, approved, _ = make_approval(task_a, bundle, strict_task=th_a,
                                          strict_evid=root)
        assert approved is True
        record, verdict, _, _ = seal(task_b, bundle, pol, appr, ledger)
        assert verdict == "BLOCKED"
        assert "TASK_BINDING_MISMATCH" in record["verdict"]["reasons"]


def test_sealer_seal_time_double_swap_is_blocked():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task_a, th_a = make_task(amount=1840.00)
        task_b, _ = make_task(amount=2000.00)
        bundle_a, root_a, _ = make_bundle()
        bundle_b, _, _ = make_bundle(items=[
            make_evidence(claim="other", content="other content",
                          source="https://x.example/9"),
            make_evidence(claim="more", content="more content",
                          source="https://x.example/10"),
        ])
        pol = make_policy_result(task_b, bundle_b)
        appr, _, _ = make_approval(task_a, bundle_a, strict_task=th_a,
                                   strict_evid=root_a)
        record, verdict, _, _ = seal(task_b, bundle_b, pol, appr, ledger)
        assert verdict == "BLOCKED"
        assert "APPROVAL_BINDING_MISMATCH" in record["verdict"]["reasons"]


def test_sealer_signs_when_key_provided():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        key_path = os.path.join(td, "hmac.key")
        with open(key_path, "wb") as f:
            f.write(b"0123456789abcdef0123456789abcdef")
        task, th = make_task()
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        record, _, rh, _ = seal(task, bundle, pol, appr, ledger,
                                key_path=key_path)
        sig = record["integrity"]["signature"]
        assert sig is not None
        key, _ = core.load_hmac_key(key_path)
        assert core.hmac_verify(rh, sig, key)


# ---------------------------------------------------------------------------
# Ledger: append, chaining, idempotency, tamper detection
# ---------------------------------------------------------------------------

def _sealed_record(ledger, amount=1840.00):
    record, _, _, _ = full_run(ledger, amount=amount)
    return record


def test_ledger_chain_append_and_idempotency():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()

        r1 = _sealed_record(ledger, amount=100.00)
        path1, pos1, h1, status1 = writer.run(record=r1, ledger_path=ledger)
        assert pos1 == 0 and status1 == "APPENDED"

        _, pos_dup, _, status_dup = writer.run(record=r1, ledger_path=ledger)
        assert status_dup == "DUPLICATE_SKIPPED" and pos_dup == 0

        r2 = _sealed_record(ledger, amount=200.00)
        assert r2["chain"]["prev_record_hash"] == h1  # chained to the tail
        _, pos2, h2, status2 = writer.run(record=r2, ledger_path=ledger)
        assert pos2 == 1 and status2 == "APPENDED"

        result = core.validate_chain(core.ledger_read(ledger))
        assert result["valid"] is True and result["length"] == 2


def test_ledger_tamper_detection():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)

        with open(ledger, "r", encoding="utf-8") as f:
            lines = f.readlines()
        rec0 = json.loads(lines[0])
        rec0["task"]["amount"] = 999999.99
        lines[0] = json.dumps(rec0, ensure_ascii=False) + "\n"
        with open(ledger, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = core.validate_chain(core.ledger_read(ledger))
        codes = [e["code"] for e in result["errors"]]
        assert result["valid"] is False
        assert "HASH_MISMATCH" in codes

        validator = opl_nodes.OplChainValidator()
        valid, report, length = validator.run(ledger_path=ledger,
                                              hmac_key_path="")
        assert valid is False and length == 2
        assert "HASH_MISMATCH" in report


def test_ledger_truncation_breaks_chain():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)

        with open(ledger, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(ledger, "w", encoding="utf-8") as f:
            f.writelines(lines[1:])

        result = core.validate_chain(core.ledger_read(ledger))
        codes = [e["code"] for e in result["errors"]]
        assert result["valid"] is False
        assert "CHAIN_BREAK" in codes


def test_ledger_rename_during_runtime_starts_fresh_at_genesis():
    """Regression for the live-test finding: after the ledger file is
    renamed while the process keeps running, the next sealed record at the
    original path must chain from GENESIS (the actual current file state),
    not from a stale in-memory tail, and the new ledger must pass CLI
    validation. The old renamed ledger must remain independently valid."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)

        renamed = os.path.join(td, "ledger_tampered.jsonl")
        os.rename(ledger, renamed)  # process continues, same paths in use

        # Seal a new record against the ORIGINAL path: the tail read must
        # reflect the now-missing file, so prev must be GENESIS.
        record = _sealed_record(ledger, 300.00)
        assert record["chain"]["prev_record_hash"] == core.GENESIS
        _, pos, _, status = writer.run(record=record, ledger_path=ledger)
        assert status == "APPENDED" and pos == 0

        cli = os.path.join(ROOT, "oplogica_core.py")
        for path, n in ((ledger, 1), (renamed, 2)):
            res = subprocess.run([sys.executable, cli, "verify", path],
                                 capture_output=True, text=True)
            assert res.returncode == 0, res.stdout + res.stderr
            assert ("records=%d" % n) in res.stdout


def test_ledger_delete_during_runtime_starts_fresh_at_genesis():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        os.remove(ledger)
        record = _sealed_record(ledger, 200.00)
        assert record["chain"]["prev_record_hash"] == core.GENESIS
        _, pos, _, status = writer.run(record=record, ledger_path=ledger)
        assert status == "APPENDED" and pos == 0
        result = core.validate_chain(core.ledger_read(ledger))
        assert result["valid"] is True and result["length"] == 1
        # An empty (zero-byte) file must also mean GENESIS.
        open(ledger, "w").close()
        record2 = _sealed_record(ledger, 300.00)
        assert record2["chain"]["prev_record_hash"] == core.GENESIS


def test_ledger_path_switch_starts_new_chain_at_genesis():
    """Switching the ledger path to a new file B must start B at GENESIS
    regardless of how many records ledger A holds."""
    with tempfile.TemporaryDirectory() as td:
        ledger_a = os.path.join(td, "ledger_a.jsonl")
        ledger_b = os.path.join(td, "ledger_b.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger_a, 100.00),
                   ledger_path=ledger_a)
        writer.run(record=_sealed_record(ledger_a, 200.00),
                   ledger_path=ledger_a)

        record_b = _sealed_record(ledger_b, 300.00)
        assert record_b["chain"]["prev_record_hash"] == core.GENESIS
        _, pos, _, status = writer.run(record=record_b, ledger_path=ledger_b)
        assert status == "APPENDED" and pos == 0
        res_b = core.validate_chain(core.ledger_read(ledger_b))
        assert res_b["valid"] is True and res_b["length"] == 1
        res_a = core.validate_chain(core.ledger_read(ledger_a))
        assert res_a["valid"] is True and res_a["length"] == 2


def test_writer_rejects_stale_prev_instead_of_planting_chain_break():
    """Defense in depth for any cache layer: a record sealed against a tail
    that no longer exists must be rejected at append time, never written."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)

        # Seal while the old tail exists (this record declares prev=tail).
        stale_record = _sealed_record(ledger, 200.00)
        assert stale_record["chain"]["prev_record_hash"] != core.GENESIS

        # The file is renamed AFTER sealing, BEFORE appending.
        os.rename(ledger, os.path.join(td, "moved.jsonl"))
        _, pos, _, status = writer.run(record=stale_record,
                                       ledger_path=ledger)
        assert status == "STALE_PREV_REJECTED" and pos == -1
        assert not os.path.exists(ledger)  # nothing was written

        # Re-sealing against the current state recovers cleanly.
        fresh = _sealed_record(ledger, 200.00)
        assert fresh["chain"]["prev_record_hash"] == core.GENESIS
        _, pos2, _, status2 = writer.run(record=fresh, ledger_path=ledger)
        assert status2 == "APPENDED" and pos2 == 0
        result = core.validate_chain(core.ledger_read(ledger))
        assert result["valid"] is True and result["length"] == 1


def test_filesystem_dependent_nodes_force_reexecution():
    """The Sealer, Writer, and Validator read or write external mutable
    state, so all three must defeat ComfyUI's output cache via IS_CHANGED
    returning NaN (NaN != NaN means always re-execute)."""
    for cls in (opl_nodes.OplDecisionSealer,
                opl_nodes.OplAuditLedgerWriter,
                opl_nodes.OplChainValidator):
        assert hasattr(cls, "IS_CHANGED"), cls.__name__
        v = cls.IS_CHANGED()
        assert v != v, cls.__name__  # NaN is the only value where x != x


def test_cli_verifier_after_schema_change():
    """The CLI verifier must still validate a ledger containing the new
    v2 approval fields, and must fail with a nonzero exit on tampering."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)

        cli = os.path.join(ROOT, "oplogica_core.py")
        ok = subprocess.run([sys.executable, cli, "verify", ledger],
                            capture_output=True, text=True)
        assert ok.returncode == 0, ok.stdout + ok.stderr

        with open(ledger, "r", encoding="utf-8") as f:
            lines = f.readlines()
        rec0 = json.loads(lines[0])
        rec0["task"]["amount"] = 31337.00
        lines[0] = json.dumps(rec0, ensure_ascii=False) + "\n"
        with open(ledger, "w", encoding="utf-8") as f:
            f.writelines(lines)
        bad = subprocess.run([sys.executable, cli, "verify", ledger],
                             capture_output=True, text=True)
        assert bad.returncode != 0


# ---------------------------------------------------------------------------
# Evidence Collector
# ---------------------------------------------------------------------------

def test_collector_deduplicates():
    e = make_evidence(claim="same", content="same content")
    bundle, _, _ = make_bundle(items=[e, dict(e), make_evidence(
        claim="other", content="other content")])
    assert bundle["stats"]["unique_count"] == 2
    assert bundle["stats"]["duplicates_removed"] == 1


def test_collector_flags_stale_and_missing_source():
    stale = make_evidence(claim="old", content="old content",
                          collected_at="2024-01-01T00:00:00Z")
    nosrc = make_evidence(claim="bare", content="bare content", source="")
    bundle, root, report = make_bundle(items=[stale, nosrc])
    assert bundle["stats"]["stale_count"] == 1
    assert bundle["stats"]["missing_source_count"] == 1
    assert "WARN" in report
    item_hashes = sorted(i["item_hash"] for i in bundle["items"])
    assert root == core.merkle_root(item_hashes)


def test_collector_root_is_order_independent():
    """The bundle root identifies the evidence SET: wiring the same items
    into different input slots must produce the same Merkle root, so a
    legitimate approval cannot be invalidated by re-wiring order."""
    e1 = make_evidence(claim="alpha", content="alpha content",
                       source="https://x.example/a")
    e2 = make_evidence(claim="beta", content="beta content",
                       source="https://x.example/b")
    _, root_ab, _ = make_bundle(items=[e1, e2])
    _, root_ba, _ = make_bundle(items=[e2, e1])
    assert root_ab == root_ba


def test_collector_content_change_changes_root():
    e1 = make_evidence(claim="alpha", content="alpha content",
                       source="https://x.example/a")
    e2 = make_evidence(claim="beta", content="beta content",
                       source="https://x.example/b")
    e2_changed = make_evidence(claim="beta", content="beta content EDITED",
                               source="https://x.example/b")
    _, root_1, _ = make_bundle(items=[e1, e2])
    _, root_2, _ = make_bundle(items=[e1, e2_changed])
    assert root_1 != root_2


# ---------------------------------------------------------------------------
# Node contracts (ComfyUI interface shape)
# ---------------------------------------------------------------------------

def test_node_contracts():
    assert len(opl_nodes.NODE_CLASS_MAPPINGS) == 10
    for name, cls in opl_nodes.NODE_CLASS_MAPPINGS.items():
        it = cls.INPUT_TYPES()
        assert isinstance(it, dict) and "required" in it, name
        assert isinstance(cls.RETURN_TYPES, tuple), name
        names = getattr(cls, "RETURN_NAMES", cls.RETURN_TYPES)
        assert len(names) == len(cls.RETURN_TYPES), name
        fn = getattr(cls, "FUNCTION")
        assert callable(getattr(cls, fn)), name
        assert name in opl_nodes.NODE_DISPLAY_NAME_MAPPINGS, name
        assert cls.CATEGORY.startswith("Oplogica"), name


def test_gate_exposes_both_strict_fields():
    it = opl_nodes.OplHumanApprovalGate.INPUT_TYPES()
    req = it["required"]
    assert "strict_expected_task_hash" in req
    assert "strict_expected_evidence_root" in req
    assert "bundle" in req  # evidence is mandatory for evidence-bound approval
    assert req["decision"][1]["default"] == "PENDING"


def test_text_display_ui_payload():
    node = opl_nodes.OplTextDisplay()
    out = node.run(text="hello ledger")
    assert out["ui"]["text"] == ["hello ledger"]
    assert out["result"] == ("hello ledger",)


# ---------------------------------------------------------------------------
# Workflow JSON consistency and demo safety
# ---------------------------------------------------------------------------

def test_workflow_json_matches_node_definitions():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_workflow  # noqa: E402

    wf = build_workflow.build()
    by_id = {n["id"]: n for n in wf["nodes"]}

    for node in wf["nodes"]:
        if node["type"] == "PreviewImage":
            continue
        cls = opl_nodes.NODE_CLASS_MAPPINGS[node["type"]]
        conns, widgets = build_workflow.split_inputs(cls)
        assert len(node["widgets_values"]) == len(widgets), node["type"]
        assert [i["name"] for i in node["inputs"]] == [c[0] for c in conns], \
            node["type"]

    for lid, frm, fslot, to, tslot, ltype in wf["links"]:
        src, dst = by_id[frm], by_id[to]
        assert src["outputs"][fslot]["type"] == ltype
        assert dst["inputs"][tslot]["type"] == ltype
        assert dst["inputs"][tslot]["link"] == lid
        assert lid in src["outputs"][fslot]["links"]


def test_default_workflow_is_safe_pass_one():
    """The shipped demo must start in PENDING with no pre-filled approver
    and empty strict fields: a safe pass-1, never an open-mode APPROVED."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_workflow  # noqa: E402

    wf = build_workflow.build()
    gate = next(n for n in wf["nodes"]
                if n["type"] == "OplHumanApprovalGate")
    _, widgets = build_workflow.split_inputs(opl_nodes.OplHumanApprovalGate)
    names = [w[0] for w in widgets]
    vals = gate["widgets_values"]
    assert vals[names.index("decision")] == "PENDING"
    assert vals[names.index("approver")] == ""
    assert vals[names.index("strict_expected_task_hash")] == ""
    assert vals[names.index("strict_expected_evidence_root")] == ""


# ---------------------------------------------------------------------------
# Card renderer (PIL only; no torch required)
# ---------------------------------------------------------------------------

def test_card_renderer_approved_and_blocked():
    from oplogica_render import render_card
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        approved_record, v1, _, _ = full_run(ledger)
        assert v1 == "APPROVED"
        img1 = render_card(approved_record)
        assert img1.size == (1200, 675) and img1.mode == "RGB"

        # BLOCKED with a binding mismatch reason.
        task, th = make_task()
        reviewed_bundle, r1, _ = make_bundle()
        changed_bundle, r2, _ = make_bundle(items=[
            make_evidence(claim="changed", content="changed content",
                          source="https://x.example/z"),
            make_evidence(claim="claim two", content="content two",
                          source="https://x.example/2"),
        ])
        pol = make_policy_result(task, changed_bundle)
        appr, _, _ = make_approval(task, changed_bundle, strict_task=th,
                                   strict_evid=r1)
        blocked_record, v2, _, _ = seal(task, changed_bundle, pol, appr,
                                        ledger)
        assert v2 == "BLOCKED"
        img2 = render_card(blocked_record)
        assert img2.size == (1200, 675) and img2.mode == "RGB"


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def _main():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS  %s" % name)
        except AssertionError as e:
            failures += 1
            print("FAIL  %s :: %s" % (name, e))
        except Exception as e:
            failures += 1
            print("ERROR %s :: %r" % (name, e))
    print("-" * 60)
    print("%d test(s), %d failure(s)" % (len(tests), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_main())
