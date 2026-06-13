#!/usr/bin/env python3
"""
Oplogica ComfyUI extension test suite (pack version 1.1.0).

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
                  strict_task="", strict_evid="", note="",
                  strict_output="", output=None):
    node = opl_nodes.OplHumanApprovalGate()
    approval, approved, report = node.run(
        task=task, bundle=bundle, decision=decision, approver=approver,
        note=note, strict_expected_task_hash=strict_task,
        strict_expected_evidence_root=strict_evid,
        strict_expected_output_hash=strict_output, output=output)
    return approval, approved, report


def seal(task, bundle, policy_result, approval, ledger_path, key_path="",
         output=None, graph=None, generation=None):
    node = opl_nodes.OplDecisionSealer()
    return node.run(task=task, bundle=bundle, policy_result=policy_result,
                    approval=approval, ledger_path=ledger_path,
                    hmac_key_path=key_path, output=output, graph=graph,
                    generation=generation)


def make_output(text="PAY Acme Cloud 1840.00 USD ref INV-2291"):
    out, oh, _ = opl_nodes.OplOutputBinder().run(text_artifact=text,
                                                 artifact_path="")
    return out, oh


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
        assert ap["schema"] == "oplogica.approval.v3"


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
    assert len(opl_nodes.NODE_CLASS_MAPPINGS) == 14
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
    assert "strict_expected_output_hash" in req
    assert "output" in it.get("optional", {})
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
        if node["type"] not in opl_nodes.NODE_CLASS_MAPPINGS:
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
# v1.1.0: output binding
# ---------------------------------------------------------------------------

def test_output_binder_text_and_file_hashing():
    out1, h1 = make_output("instruction A")
    out2, h2 = make_output("instruction A")
    out3, h3 = make_output("instruction B")
    assert h1 == h2 and h1 != h3
    assert out1["output_kind"] == "text"
    assert out1["summary"]["excerpt"] == "instruction A"
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "artifact.bin")
        with open(fp, "wb") as f:
            f.write(b"artifact-bytes")
        out, oh, _ = opl_nodes.OplOutputBinder().run(
            text_artifact="", artifact_path=fp)
        assert out["output_kind"] == "file"
        assert oh == core.sha256_hex(b"artifact-bytes")


def test_output_binder_image_hash_deterministic_and_sensitive():
    import numpy as np
    img = np.zeros((1, 8, 8, 3), dtype=np.float32)
    img[0, 2, 3, 0] = 0.5
    out_a, ha, _ = opl_nodes.OplOutputBinder().run(
        text_artifact="", artifact_path="", image=img)
    out_b, hb, _ = opl_nodes.OplOutputBinder().run(
        text_artifact="", artifact_path="", image=img.copy())
    assert ha == hb and out_a["output_kind"] == "image"
    assert out_a["summary"] == {"height": 8, "width": 8}
    img2 = img.copy()
    img2[0, 2, 3, 0] = 0.9  # one pixel changes
    _, hc, _ = opl_nodes.OplOutputBinder().run(
        text_artifact="", artifact_path="", image=img2)
    assert hc != ha
    # Equivalent uint8 content hashes identically to the float form.
    img_u8 = (np.clip(img[0] * 255.0 + 0.5, 0, 255)).astype(np.uint8)
    _, hd, _ = opl_nodes.OplOutputBinder().run(
        text_artifact="", artifact_path="", image=img_u8)
    assert hd == ha


def test_gate_output_strict_match_and_mismatch():
    task, th = make_task()
    bundle, root, _ = make_bundle()
    out, oh = make_output()
    appr, approved, report = make_approval(task, bundle, strict_task=th,
                                           strict_evid=root,
                                           strict_output=oh, output=out)
    assert approved is True
    assert appr["bound_output_hash"] == oh
    assert appr["output_binding"] == "enforced"
    assert oh in report
    reviewed_out, reviewed_hash = make_output("what the human reviewed")
    appr2, approved2, _ = make_approval(task, bundle, strict_task=th,
                                        strict_evid=root,
                                        strict_output=reviewed_hash,
                                        output=out)
    assert approved2 is False
    assert appr2["downgrade_reason"].startswith("OUTPUT_BINDING_MISMATCH")
    assert appr2["output_binding_ok"] is False


def test_gate_task_mismatch_takes_precedence_over_output():
    task, _ = make_task(amount=9999.00)
    bundle, root, _ = make_bundle()
    out, oh = make_output()
    appr, approved, _ = make_approval(
        task, bundle, strict_task=core.hash_obj({"old": "task"}),
        strict_evid=root, strict_output=core.hash_obj({"old": "out"}),
        output=out)
    assert approved is False
    assert appr["downgrade_reason"].startswith("TASK_BINDING_MISMATCH")
    assert appr["output_binding_ok"] is False  # detail retained per flag


def test_sealer_blocks_output_swap_and_missing_output():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()
        bundle, root, _ = make_bundle()
        out_a, ha = make_output("artifact A")
        out_b, hb = make_output("artifact B")
        pol = make_policy_result(task, bundle)
        appr, approved, _ = make_approval(task, bundle, strict_task=th,
                                          strict_evid=root, strict_output=ha,
                                          output=out_a)
        assert approved is True
        record, verdict, _, _ = seal(task, bundle, pol, appr, ledger,
                                     output=out_b)
        assert verdict == "BLOCKED"
        assert "OUTPUT_BINDING_MISMATCH" in record["verdict"]["reasons"]
        record2, verdict2, _, _ = seal(task, bundle, pol, appr, ledger,
                                       output=None)
        assert verdict2 == "BLOCKED"
        assert "OUTPUT_BINDING_MISMATCH" in record2["verdict"]["reasons"]
        record3, verdict3, _, _ = seal(task, bundle, pol, appr, ledger,
                                       output=out_a)
        assert verdict3 == "APPROVED"
        assert record3["output"]["output_hash"] == ha


# ---------------------------------------------------------------------------
# v1.1.0: workflow graph attestation
# ---------------------------------------------------------------------------

def _demo_prompt(seed=7, gate_decision="PENDING", extra_node=False):
    prompt = {
        "1": {"class_type": "OplTaskInput",
              "inputs": {"actor": "a", "amount": 1.0}},
        "2": {"class_type": "KSampler",
              "inputs": {"seed": seed, "model": ["9", 0]}},
        "3": {"class_type": "OplHumanApprovalGate",
              "inputs": {"decision": gate_decision, "approver": "x",
                         "task": ["1", 0]}},
        "9": {"class_type": "CheckpointLoaderSimple",
              "inputs": {"ckpt_name": "m.safetensors"}},
    }
    if extra_node:
        prompt["4"] = {"class_type": "OplTextDisplay",
                       "inputs": {"text": ["3", 2]}}
    return prompt


def test_graph_hash_stable_and_excludes_review_channel():
    h1, n1, l1 = core.canonical_graph_hash(_demo_prompt())
    # Key order independence: rebuild with reversed insertion order.
    rev = dict(reversed(list(_demo_prompt().items())))
    h2, _, _ = core.canonical_graph_hash(rev)
    assert h1 == h2 and n1 == 4 and l1 == 2
    # Changing the gate's own widget values must not change the hash.
    h3, _, _ = core.canonical_graph_hash(
        _demo_prompt(gate_decision="APPROVED"))
    assert h3 == h1
    # Changing any other widget value must change the hash.
    h4, _, _ = core.canonical_graph_hash(_demo_prompt(seed=8))
    assert h4 != h1
    # Adding a node (rewiring the structure) must change the hash.
    h5, _, _ = core.canonical_graph_hash(_demo_prompt(extra_node=True))
    assert h5 != h1


def test_attestor_enforces_structure_at_seal_time():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        attestor = opl_nodes.OplGraphAttestor()

        reviewed_graph, reviewed_hash, _ = attestor.run(
            "", prompt=_demo_prompt())
        assert reviewed_graph["attested"] is True

        # Pass 2 on the SAME structure: enforced and matching.
        same_graph, _, _ = attestor.run(reviewed_hash,
                                        prompt=_demo_prompt())
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        record, verdict, _, _ = seal(task, bundle, pol, appr, ledger,
                                     graph=same_graph)
        assert verdict == "APPROVED"
        assert record["workflow"]["match"] is True

        # Pass 2 after the structure changed: blocked.
        changed_graph, _, _ = attestor.run(
            reviewed_hash, prompt=_demo_prompt(extra_node=True))
        assert changed_graph["match"] is False
        record2, verdict2, _, _ = seal(task, bundle, pol, appr, ledger,
                                       graph=changed_graph)
        assert verdict2 == "BLOCKED"
        assert "WORKFLOW_BINDING_MISMATCH" in record2["verdict"]["reasons"]


def test_attestor_without_prompt_is_recorded_not_blocking():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        graph, gh, _ = opl_nodes.OplGraphAttestor().run("", prompt=None)
        assert graph["attested"] is False and gh == ""
        task, th = make_task()
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        record, verdict, _, _ = seal(task, bundle, pol, appr, ledger,
                                     graph=graph)
        assert verdict == "APPROVED"
        assert record["workflow"]["attested"] is False


# ---------------------------------------------------------------------------
# v1.1.0: generation context
# ---------------------------------------------------------------------------

def test_generation_context_hash_and_text_privacy():
    node = opl_nodes.OplGenerationContext()
    secret_tail = "SECRET-PROMPT-TAIL-7741"
    long_pos = ("a" * 120) + secret_tail
    gen1, ch1 = node.run(model_name="m", sampler="euler", scheduler="normal",
                         seed=7, steps=20, cfg=7.0, positive_text=long_pos,
                         negative_text="bad", extra_json="{}")
    gen2, ch2 = node.run(model_name="m", sampler="euler", scheduler="normal",
                         seed=8, steps=20, cfg=7.0, positive_text=long_pos,
                         negative_text="bad", extra_json="{}")
    assert ch1 != ch2  # the seed is part of the context identity
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        record, verdict, _, record_json = seal(task, bundle, pol, appr,
                                               ledger, generation=gen1)
        assert verdict == "APPROVED"
        assert record["generation"]["seed"] == 7
        # Full text never enters the record: hash plus 96-char excerpt only.
        assert secret_tail not in record_json
        assert core.sha256_hex(long_pos) in record_json


# ---------------------------------------------------------------------------
# v1.1.0: decision passport and standalone verifier
# ---------------------------------------------------------------------------

def test_passport_build_and_verify_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)
        passport = core.build_passport(ledger, 1)
        assert passport["chain_context"]["position"] == 1
        assert passport["chain_context"]["prev_record"] is not None
        result = core.verify_passport(passport)
        assert result["valid"] is True, result
        names = [c["name"] for c in result["checks"]]
        assert "chain_link" in names and "record_hash" in names

        # Tamper with a sealed field inside the passport: must go invalid.
        bad = json.loads(json.dumps(passport))
        bad["record"]["task"]["amount"] = 31337.0
        result_bad = core.verify_passport(bad)
        assert result_bad["valid"] is False

        # Break the chain context: must go invalid.
        bad2 = json.loads(json.dumps(passport))
        bad2["record"]["chain"]["prev_record_hash"] = "f" * 64
        assert core.verify_passport(bad2)["valid"] is False


def test_passport_verifies_signature_with_key():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        key_path = os.path.join(td, "k.key")
        key = b"0123456789abcdef0123456789abcdef"
        with open(key_path, "wb") as f:
            f.write(key)
        task, th = make_task()
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        record, _, _, _ = seal(task, bundle, pol, appr, ledger,
                               key_path=key_path)
        opl_nodes.OplAuditLedgerWriter().run(record=record,
                                             ledger_path=ledger)
        passport = core.build_passport(ledger, 0)
        assert core.verify_passport(passport, key=key)["valid"] is True
        assert core.verify_passport(
            passport, key=b"ffffffffffffffffffffffffffffffff")["valid"] is False


def test_passport_cli_roundtrip_and_tamper():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        cli = os.path.join(ROOT, "oplogica_core.py")
        ppath = os.path.join(td, "passport.json")
        made = subprocess.run([sys.executable, cli, "passport", ledger,
                               "-o", ppath], capture_output=True, text=True)
        assert made.returncode == 0 and os.path.exists(ppath), made.stderr
        ok = subprocess.run([sys.executable, cli, "verify-passport", ppath],
                            capture_output=True, text=True)
        assert ok.returncode == 0, ok.stdout + ok.stderr
        with open(ppath, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["record"]["task"]["amount"] = 1.0
        with open(ppath, "w", encoding="utf-8") as f:
            json.dump(data, f)
        bad = subprocess.run([sys.executable, cli, "verify-passport", ppath],
                             capture_output=True, text=True)
        assert bad.returncode != 0


def test_passport_exporter_node():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record = _sealed_record(ledger, 100.00)
        opl_nodes.OplAuditLedgerWriter().run(record=record,
                                             ledger_path=ledger)
        exporter = opl_nodes.OplPassportExporter()
        path, status, text = exporter.run(record=record, ledger_path=ledger,
                                          passport_dir=td)
        assert status == "EXPORTED" and os.path.exists(path)
        assert core.verify_passport(json.loads(text))["valid"] is True
        # Record not in the ledger: chain-context-free export still works.
        orphan = _sealed_record(os.path.join(td, "other.jsonl"), 50.00)
        path2, status2, text2 = exporter.run(record=orphan,
                                             ledger_path=ledger,
                                             passport_dir=td)
        assert status2 == "EXPORTED_WITHOUT_CHAIN_CONTEXT"
        assert core.verify_passport(json.loads(text2))["valid"] is True


def test_verifier_html_is_local_only():
    path = os.path.join(ROOT, "verifier", "verifier.html")
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    assert "<script src=" not in html
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html
    assert "PASSPORT VALID" in html
    assert "Integrity is not truth" in html


# ---------------------------------------------------------------------------
# v1.1.0: compatibility and packaging
# ---------------------------------------------------------------------------

def test_v1_records_without_new_sections_still_validate():
    """A v1.0.0-style record (no output, workflow, or generation section)
    chains and validates unchanged: the schema extension is additive."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        task, th = make_task()
        bundle, root, _ = make_bundle()
        pol = make_policy_result(task, bundle)
        appr, _, _ = make_approval(task, bundle, strict_task=th,
                                   strict_evid=root)
        old_style = core.seal_record(
            task=task, evidence_summary={"merkle_root": root, "stats": {},
                                         "items": []},
            checks={"policy": pol}, approvals=[appr],
            verdict={"status": "APPROVED", "reasons": [],
                     "requires_human": True},
            prev_hash=core.GENESIS)
        assert "output" not in old_style and "workflow" not in old_style
        pos, status = core.ledger_append(ledger, old_style)
        assert status == "APPENDED"
        new_record = _sealed_record(ledger, 200.00)
        core.ledger_append(ledger, new_record)
        result = core.validate_chain(core.ledger_read(ledger))
        assert result["valid"] is True and result["length"] == 2


def test_image_demo_workflow_consistency():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_workflow  # noqa: E402

    wf = build_workflow.build_image_demo()
    by_id = {n["id"]: n for n in wf["nodes"]}
    for node in wf["nodes"]:
        if node["type"] not in opl_nodes.NODE_CLASS_MAPPINGS:
            continue  # base ComfyUI nodes ship as a static reference spec
        cls = opl_nodes.NODE_CLASS_MAPPINGS[node["type"]]
        conns, widgets = build_workflow.split_inputs(cls)
        assert len(node["widgets_values"]) == len(widgets), node["type"]
        assert [i["name"] for i in node["inputs"]] == [c[0] for c in conns], \
            node["type"]
    for lid, frm, fslot, to, tslot, ltype in wf["links"]:
        src, dst = by_id[frm], by_id[to]
        assert src["outputs"][fslot]["type"] == ltype
        assert dst["inputs"][tslot]["type"] == ltype
    # The decision layer is wired end to end.
    sealer = next(n for n in wf["nodes"] if n["type"] == "OplDecisionSealer")
    linked = [i["name"] for i in sealer["inputs"] if i["link"] is not None]
    for name in ("task", "bundle", "policy_result", "approval", "output",
                 "graph", "generation"):
        assert name in linked, name


def test_tamper_pack_builder():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_tamper_pack  # noqa: E402

    with tempfile.TemporaryDirectory() as td:
        out = build_tamper_pack.main(os.path.join(td, "pack"))
        names = sorted(os.listdir(out))
        for d in ("01_clean", "02_ledger_tampered", "03_wrong_key",
                  "04_changed_evidence", "05_changed_task",
                  "06_changed_output"):
            assert d in names, names
        assert "README.md" in names
        clean = core.validate_chain(core.ledger_read(
            os.path.join(out, "01_clean", "ledger.jsonl")),
            key=build_tamper_pack.DEMO_KEY_CORRECT)
        assert clean["valid"] and clean["signatures_checked"] == 2
        tampered = core.validate_chain(core.ledger_read(
            os.path.join(out, "02_ledger_tampered", "ledger.jsonl")))
        assert tampered["valid"] is False
        rec4 = core.ledger_read(os.path.join(out, "04_changed_evidence",
                                             "ledger.jsonl"))[0]
        assert "EVIDENCE_BINDING_MISMATCH" in rec4["verdict"]["reasons"]
        rec6 = core.ledger_read(os.path.join(out, "06_changed_output",
                                             "ledger.jsonl"))[0]
        assert "OUTPUT_BINDING_MISMATCH" in rec6["verdict"]["reasons"]



# ---------------------------------------------------------------------------
# v1.1.0 release candidate: live-test regressions (imports, paths, colors)
# ---------------------------------------------------------------------------

import contextlib


@contextlib.contextmanager
def fake_comfyui_output_dir(path):
    """Inject a minimal folder_paths module so resolve_output_path behaves
    exactly as inside ComfyUI, with the output directory at `path`."""
    import types
    mod = types.ModuleType("folder_paths")
    mod.get_output_directory = lambda: path
    saved = sys.modules.get("folder_paths")
    sys.modules["folder_paths"] = mod
    try:
        yield path
    finally:
        if saved is None:
            del sys.modules["folder_paths"]
        else:
            sys.modules["folder_paths"] = saved


def test_package_relative_imports_comfyui_style():
    """Load the repository exactly the way ComfyUI loads a custom node
    package (spec_from_file_location on __init__.py, no repo on sys.path,
    no cached top-level modules) and exercise the Passport Exporter branch
    that previously failed with ModuleNotFoundError in the live test."""
    script = """
import importlib.util, json, os, sys, tempfile
root = sys.argv[1]
spec = importlib.util.spec_from_file_location(
    "oplogica_pkg_test", os.path.join(root, "__init__.py"),
    submodule_search_locations=[root])
mod = importlib.util.module_from_spec(spec)
sys.modules["oplogica_pkg_test"] = mod
spec.loader.exec_module(mod)
M = mod.NODE_CLASS_MAPPINGS
assert len(M) == 14, len(M)
task, th = M["OplTaskInput"]().run(
    actor="a", actor_type="ai_agent", action_type="payment.vendor",
    amount=10.0, currency="USD", payload_json="{}", risk_hint="low")
(e1,) = M["OplEvidenceItem"]().run(
    claim="c", source_url="https://example.com/x", content="body",
    collected_at="")
(e2,) = M["OplEvidenceItem"]().run(
    claim="d", source_url="https://example.com/y", content="body2",
    collected_at="")
bundle, root_hash, _ = M["OplEvidenceCollector"]().run(
    evidence_1=e1, evidence_2=e2, max_age_days=90, require_source=True)
pol, _, _ = M["OplPolicyCheck"]().run(
    task=task, bundle=bundle,
    policy_json=open(os.path.join(root, "policies",
                                  "default_policy.json")).read())
appr, ok, _ = M["OplHumanApprovalGate"]().run(
    task=task, bundle=bundle, decision="APPROVED", approver="x", note="",
    strict_expected_task_hash=th, strict_expected_evidence_root=root_hash,
    strict_expected_output_hash="")
with tempfile.TemporaryDirectory() as td:
    record, verdict, rh, _ = M["OplDecisionSealer"]().run(
        task=task, bundle=bundle, policy_result=pol, approval=appr,
        ledger_path=os.path.join(td, "l.jsonl"), hmac_key_path="")
    # Orphan record (not written to any ledger): this is exactly the
    # branch that contained the package-unsafe absolute import.
    path, status, text = M["OplPassportExporter"]().run(
        record=record, ledger_path=os.path.join(td, "missing.jsonl"),
        passport_dir=td)
    assert status == "EXPORTED_WITHOUT_CHAIN_CONTEXT", status
    assert os.path.exists(path)
    json.loads(text)
print("PACKAGE_IMPORT_OK")
"""
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "load_as_package.py")
        with open(sp, "w", encoding="utf-8") as f:
            f.write(script)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        proc = subprocess.run([sys.executable, sp, ROOT], cwd=td,
                              capture_output=True, text=True, env=env)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "PACKAGE_IMPORT_OK" in proc.stdout


def test_hmac_key_relative_resolves_from_comfyui_output_dir():
    with tempfile.TemporaryDirectory() as td:
        out_dir = os.path.join(td, "output")
        os.makedirs(os.path.join(out_dir, "oplogica"))
        key = b"0123456789abcdef0123456789abcdef"
        with open(os.path.join(out_dir, "oplogica", "hmac.key"), "wb") as f:
            f.write(key)
        with fake_comfyui_output_dir(out_dir):
            loaded = core.load_hmac_key("oplogica/hmac.key")
        assert loaded is not None and loaded[0] == key


def test_hmac_key_cwd_relative_still_works_for_cli():
    with tempfile.TemporaryDirectory() as td:
        key = b"0123456789abcdef0123456789abcdef"
        with open(os.path.join(td, "k.key"), "wb") as f:
            f.write(key)
        cwd = os.getcwd()
        os.chdir(td)
        try:
            loaded = core.load_hmac_key("k.key")
        finally:
            os.chdir(cwd)
        assert loaded is not None and loaded[0] == key


def test_hmac_key_absolute_path_and_actionable_missing_error():
    with tempfile.TemporaryDirectory() as td:
        key = b"0123456789abcdef0123456789abcdef"
        abs_path = os.path.join(td, "k.key")
        with open(abs_path, "wb") as f:
            f.write(key)
        assert core.load_hmac_key(abs_path)[0] == key
        with fake_comfyui_output_dir(os.path.join(td, "output")):
            try:
                core.load_hmac_key("oplogica/missing.key")
                assert False, "expected FileNotFoundError"
            except FileNotFoundError as e:
                msg = str(e)
        # The error names every resolved candidate, absolute.
        assert os.path.abspath("oplogica/missing.key") in msg
        assert os.path.join(td, "output", "oplogica", "missing.key") in msg
        assert "output directory" in msg


def test_passport_dir_relative_resolves_from_comfyui_output_dir():
    it = opl_nodes.OplPassportExporter.INPUT_TYPES()
    assert it["required"]["passport_dir"][1]["default"] == "oplogica"
    with tempfile.TemporaryDirectory() as td:
        out_dir = os.path.join(td, "output")
        os.makedirs(out_dir)
        with fake_comfyui_output_dir(out_dir):
            ledger_rel = "oplogica/ledger.jsonl"
            record = _sealed_record(ledger_rel, 100.00)
            opl_nodes.OplAuditLedgerWriter().run(record=record,
                                                 ledger_path=ledger_rel)
            path, status, text = opl_nodes.OplPassportExporter().run(
                record=record, ledger_path=ledger_rel,
                passport_dir="oplogica")
        assert status == "EXPORTED"
        expected_dir = os.path.join(out_dir, "oplogica")
        assert os.path.dirname(path) == expected_dir
        assert os.path.exists(path)
        assert core.verify_passport(json.loads(text))["valid"] is True


def _rel_luminance(hex_color):
    def chan(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def _contrast(hex_a, hex_b):
    la, lb = _rel_luminance(hex_a), _rel_luminance(hex_b)
    lo, hi = min(la, lb), max(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def test_node_palette_readable_in_dark_mode():
    """Every node title must read clearly against its header in dark mode
    (light title text, approximately #E8E8E8), and no node may look
    disabled: header and body differ, body darker than header."""
    title_text = "#E8E8E8"
    palette = opl_nodes.OPL_NODE_COLORS
    assert set(palette) == set(opl_nodes.NODE_CLASS_MAPPINGS)
    for name, (header, body) in palette.items():
        assert header != body, name
        assert _contrast(header, title_text) >= 4.5, \
            "%s header %s fails title contrast (%.2f)" % (
                name, header, _contrast(header, title_text))
        assert _rel_luminance(body) < _rel_luminance(header), name


def test_workflows_bake_colors_and_contain_no_machine_paths():
    for fname in ("oplogica_payment_demo.json", "oplogica_image_demo.json"):
        path = os.path.join(ROOT, "workflows", fname)
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        # Portable: no drive letters, no user-machine absolute paths.
        assert ":\\" not in raw and "/home/" not in raw, fname
        wf = json.loads(raw)
        assert wf["version"] == 0.4
        for node in wf["nodes"]:
            if node["type"] in opl_nodes.OPL_NODE_COLORS:
                header, body = opl_nodes.OPL_NODE_COLORS[node["type"]]
                assert node.get("color") == header, (fname, node["type"])
                assert node.get("bgcolor") == body, (fname, node["type"])


def test_frontend_palette_in_sync_with_python_palette():
    with open(os.path.join(ROOT, "web", "oplogica.js"), "r",
              encoding="utf-8") as f:
        js = f.read()
    for name, (header, body) in opl_nodes.OPL_NODE_COLORS.items():
        assert name in js, name
        assert header in js and body in js, (name, header, body)



# ---------------------------------------------------------------------------
# Final live test: GENESIS passport semantics and export ordering
# ---------------------------------------------------------------------------

def test_passport_genesis_first_record_verifies():
    """A passport for the first record of a fresh ledger declares GENESIS,
    embeds no predecessor, and must verify as valid."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record = _sealed_record(ledger, 100.00)
        opl_nodes.OplAuditLedgerWriter().run(record=record,
                                             ledger_path=ledger)
        passport = core.build_passport(ledger, 0)
        assert passport["chain_context"]["position"] == 0
        assert passport["chain_context"]["prev_record"] is None
        assert passport["record"]["chain"]["prev_record_hash"] == core.GENESIS
        result = core.verify_passport(passport)
        assert result["valid"] is True, result
        link = next(c for c in result["checks"] if c["name"] == "chain_link")
        assert link["passed"] and "first record" in link["detail"]


def test_passport_non_genesis_requires_and_verifies_predecessor():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)
        passport = core.build_passport(ledger, 1)
        assert passport["chain_context"]["prev_record"] is not None
        result = core.verify_passport(passport)
        assert result["valid"] is True, result
        names = [c["name"] for c in result["checks"]]
        assert "prev_record_hash" in names
        assert "prev_canonical_parity" in names


def test_passport_non_genesis_with_missing_predecessor_fails():
    """The exact failure observed in the final live test: a record that
    declares a real predecessor, exported without chain context. The
    verifier must fail chain_link with an actionable message."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)
        passport = core.build_passport(ledger, 1)
        passport["chain_context"]["prev_record"] = None
        passport["chain_context"]["prev_record_canonical_body"] = None
        passport["chain_context"]["position"] = None
        result = core.verify_passport(passport)
        assert result["valid"] is False
        link = next(c for c in result["checks"] if c["name"] == "chain_link")
        assert link["passed"] is False
        assert "declares predecessor" in link["detail"]
        assert "run_after" in link["detail"]


def test_passport_genesis_with_unexpected_predecessor_fails():
    """A GENESIS record with a predecessor injected into the passport is
    inconsistent and must fail the chain link check."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        writer = opl_nodes.OplAuditLedgerWriter()
        writer.run(record=_sealed_record(ledger, 100.00), ledger_path=ledger)
        writer.run(record=_sealed_record(ledger, 200.00), ledger_path=ledger)
        first = core.build_passport(ledger, 0)
        second = core.build_passport(ledger, 1)
        # Inject the second record as a fake predecessor of the first.
        first["chain_context"]["prev_record"] = second["record"]
        first["chain_context"]["prev_record_canonical_body"] = \
            second["record_canonical_body"]
        result = core.verify_passport(first)
        assert result["valid"] is False
        link = next(c for c in result["checks"] if c["name"] == "chain_link")
        assert link["passed"] is False


def test_passport_genesis_with_nonzero_position_fails():
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record = _sealed_record(ledger, 100.00)
        opl_nodes.OplAuditLedgerWriter().run(record=record,
                                             ledger_path=ledger)
        passport = core.build_passport(ledger, 0)
        passport["chain_context"]["position"] = 3
        result = core.verify_passport(passport)
        assert result["valid"] is False
        link = next(c for c in result["checks"] if c["name"] == "chain_link")
        assert "position" in link["detail"]


def test_unsigned_record_with_key_fails_with_clear_reason():
    """Verifying an unsigned record while providing a key is a failure by
    design (the caller asked for signature assurance that does not exist),
    and the reason must be explicit."""
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "ledger.jsonl")
        record = _sealed_record(ledger, 100.00)  # sealed without a key
        opl_nodes.OplAuditLedgerWriter().run(record=record,
                                             ledger_path=ledger)
        passport = core.build_passport(ledger, 0)
        assert core.verify_passport(passport)["valid"] is True
        result = core.verify_passport(passport, key=b"x" * 32)
        assert result["valid"] is False
        sig = next(c for c in result["checks"]
                   if c["name"] == "hmac_signature")
        assert sig["detail"] == "key provided but record is unsigned"


def test_exporter_ordering_input_and_workflow_wiring():
    """The exporter exposes run_after, and both demo workflows wire the
    writer's record_hash into it so the passport is always exported after
    the record is in the ledger (the execution order race from the final
    live test)."""
    it = opl_nodes.OplPassportExporter.INPUT_TYPES()
    assert "run_after" in it.get("optional", {})
    assert it["optional"]["run_after"][1].get("forceInput") is True
    for fname in ("oplogica_payment_demo.json", "oplogica_image_demo.json"):
        with open(os.path.join(ROOT, "workflows", fname),
                  encoding="utf-8") as f:
            wf = json.load(f)
        by_id = {n["id"]: n for n in wf["nodes"]}
        exporter = next(n for n in wf["nodes"]
                        if n["type"] == "OplPassportExporter")
        writer = next(n for n in wf["nodes"]
                      if n["type"] == "OplAuditLedgerWriter")
        ra = next(i for i in exporter["inputs"] if i["name"] == "run_after")
        assert ra["link"] is not None, fname
        link = next(l for l in wf["links"] if l[0] == ra["link"])
        assert link[1] == writer["id"], fname
        assert writer["outputs"][link[2]]["name"] == "record_hash", fname


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
