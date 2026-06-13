#!/usr/bin/env python3
"""
Runs the full Oplogica node pipeline outside ComfyUI to generate the example
artifacts shipped with the repository:

    examples/card_approved.png            APPROVED, strict dual binding
    examples/card_blocked.png             BLOCKED, reviewer REJECTED
    examples/card_evidence_mismatch.png   BLOCKED, EVIDENCE_BINDING_MISMATCH
                                          (evidence changed after review)
    examples/sample_decision_record.json
    examples/sample_ledger.jsonl          3-record chained ledger

Usage:
    python3 tools/render_samples.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import nodes as opl  # noqa: E402
from oplogica_render import render_card  # noqa: E402

EXAMPLES = os.path.join(ROOT, "examples")


def make_task(amount):
    task_node = opl.OplTaskInput()
    return task_node.run(
        actor="finops-agent-07", actor_type="ai_agent",
        action_type="payment.vendor", amount=amount, currency="USD",
        payload_json='{"vendor": "Acme Cloud", "invoice": "INV-2291"}',
        risk_hint="medium")


def make_bundle(amount, invoice_status="open"):
    ev = opl.OplEvidenceItem()
    (e1,) = ev.run(
        claim="Invoice INV-2291 issued by Acme Cloud for %.2f USD" % amount,
        source_url="https://billing.example.com/INV-2291",
        content="Acme Cloud invoice INV-2291. Amount due: %.2f USD. "
                "Service period: May 2026. Status: %s." % (amount,
                                                           invoice_status),
        collected_at="")
    (e2,) = ev.run(
        claim="Active services contract with Acme Cloud covers this invoice",
        source_url="https://contracts.example.com/ACME-2024-118",
        content="Master services agreement ACME-2024-118, active through "
                "2026-12-31, monthly cloud infrastructure services.",
        collected_at="")
    collector = opl.OplEvidenceCollector()
    bundle, root, _ = collector.run(evidence_1=e1, evidence_2=e2,
                                    max_age_days=90, require_source=True)
    return bundle, root


def gate_seal_write(task, task_hash, bundle, decision, approver,
                    strict_task, strict_evid, ledger, note="",
                    output=None, strict_output=""):
    policy = opl.OplPolicyCheck()
    policy_result, _, _ = policy.run(
        task=task, bundle=bundle, policy_json=opl.DEFAULT_POLICY_JSON)

    gate = opl.OplHumanApprovalGate()
    approval, _, _ = gate.run(
        task=task, bundle=bundle, decision=decision, approver=approver,
        note=note, strict_expected_task_hash=strict_task,
        strict_expected_evidence_root=strict_evid,
        strict_expected_output_hash=strict_output, output=output)

    sealer = opl.OplDecisionSealer()
    record, verdict, record_hash, record_json = sealer.run(
        task=task, bundle=bundle, policy_result=policy_result,
        approval=approval, ledger_path=ledger, hmac_key_path="",
        output=output)

    writer = opl.OplAuditLedgerWriter()
    writer.run(record=record, ledger_path=ledger)
    return record, verdict, record_json


def main():
    os.makedirs(EXAMPLES, exist_ok=True)
    ledger = os.path.join(EXAMPLES, "sample_ledger.jsonl")
    if os.path.exists(ledger):
        os.remove(ledger)

    # Scenario 1: strict triple binding (task, evidence, output), reviewed
    # and approved, unchanged. The output is the payment instruction the
    # run produces; in an image workflow it would be the generated image.
    task, th = make_task(1840.00)
    bundle, root = make_bundle(1840.00)
    binder = opl.OplOutputBinder()
    out_a, out_hash, _ = binder.run(
        text_artifact="PAY Acme Cloud 1840.00 USD ref INV-2291",
        artifact_path="")
    rec_a, verdict_a, record_json = gate_seal_write(
        task, th, bundle, decision="APPROVED", approver="m.ibrahim",
        strict_task=th, strict_evid=root, ledger=ledger,
        note="Invoice matches contract ACME-2024-118. Amount within policy.",
        output=out_a, strict_output=out_hash)
    render_card(rec_a).save(os.path.join(EXAMPLES, "card_approved.png"))
    with open(os.path.join(EXAMPLES, "sample_decision_record.json"),
              "w", encoding="utf-8") as f:
        f.write(record_json + "\n")

    # Scenario 2: reviewer rejects within strict binding. Chains onto 1.
    task2, th2 = make_task(4980.00)
    bundle2, root2 = make_bundle(4980.00)
    rec_b, verdict_b, _ = gate_seal_write(
        task2, th2, bundle2, decision="REJECTED", approver="m.ibrahim",
        strict_task=th2, strict_evid=root2, ledger=ledger)
    render_card(rec_b).save(os.path.join(EXAMPLES, "card_blocked.png"))

    # Scenario 3 (adversarial): the reviewer approved task hash A and
    # evidence root R1. The task is unchanged, but the evidence content
    # changed afterwards, producing root R2. The strict values from the
    # review (A, R1) no longer match the current evidence: the gate
    # downgrades and the seal is BLOCKED / EVIDENCE_BINDING_MISMATCH.
    task3, th3 = make_task(1840.00)
    _, root_reviewed = make_bundle(1840.00, invoice_status="open")
    bundle_changed, root_changed = make_bundle(1840.00,
                                               invoice_status="VOID")
    assert root_reviewed != root_changed
    rec_c, verdict_c, _ = gate_seal_write(
        task3, th3, bundle_changed, decision="APPROVED",
        approver="m.ibrahim", strict_task=th3, strict_evid=root_reviewed,
        ledger=ledger)
    render_card(rec_c).save(
        os.path.join(EXAMPLES, "card_evidence_mismatch.png"))

    # Validate the resulting 3-record chain.
    validator = opl.OplChainValidator()
    valid, report, length = validator.run(ledger_path=ledger,
                                          hmac_key_path="")
    print(report)
    assert valid and length == 3, "sample ledger must validate"
    assert verdict_a == "APPROVED"
    assert verdict_b == "BLOCKED"
    assert verdict_c == "BLOCKED"
    assert "EVIDENCE_BINDING_MISMATCH" in rec_c["verdict"]["reasons"]

    # Export a passport for the approved record so the bundled local
    # verifier has a ready example to load.
    import oplogica_core as core
    passport = core.build_passport(ledger, 0)
    with open(os.path.join(EXAMPLES, "passport_example.json"), "w",
              encoding="utf-8") as f:
        json.dump(passport, f, ensure_ascii=False, indent=2)
        f.write("\n")
    pv = core.verify_passport(passport)
    assert pv["valid"], pv

    print("Wrote examples: card_approved.png (%s), card_blocked.png (%s), "
          "card_evidence_mismatch.png (%s), sample_decision_record.json, "
          "sample_ledger.jsonl, passport_example.json" % (
              verdict_a, verdict_b, verdict_c))


if __name__ == "__main__":
    main()
