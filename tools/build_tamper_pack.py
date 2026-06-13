#!/usr/bin/env python3
"""
Builds the tamper demonstration pack: six scripted scenarios that show what
the verifier catches and exactly how it reports each failure. Everything is
generated deterministically from this script; the keys included are PUBLIC
demonstration keys and must never be used for real records.

Usage:
    python3 tools/build_tamper_pack.py            # writes examples/tamper_pack/
    python3 tools/build_tamper_pack.py /tmp/out   # custom output directory

Scenarios:
    01_clean             signed 2-record ledger, CLI verify passes
    02_ledger_tampered   record edited in place, HASH_MISMATCH
    03_wrong_key         verification with the wrong key, SIGNATURE_INVALID
    04_changed_evidence  evidence changed after review, EVIDENCE_BINDING_MISMATCH
    05_changed_task      task changed after review, TASK_BINDING_MISMATCH
    06_changed_output    output changed after review, OUTPUT_BINDING_MISMATCH
"""

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import nodes as opl  # noqa: E402
import oplogica_core as core  # noqa: E402

DEMO_KEY_CORRECT = b"OPLOGICA-DEMO-KEY-0001-PUBLIC!!!"
DEMO_KEY_WRONG = b"OPLOGICA-DEMO-KEY-0002-PUBLIC!!!"


def make_task(amount=1840.00):
    task, th = opl.OplTaskInput().run(
        actor="finops-agent-07", actor_type="ai_agent",
        action_type="payment.vendor", amount=amount, currency="USD",
        payload_json='{"vendor": "Acme Cloud", "invoice": "INV-2291"}',
        risk_hint="medium")
    return task, th


def make_bundle(status="open"):
    ev = opl.OplEvidenceItem()
    (e1,) = ev.run(claim="Invoice INV-2291 issued",
                   source_url="https://billing.example.com/INV-2291",
                   content="Invoice INV-2291. 1840.00 USD. Status: %s."
                           % status,
                   collected_at="")
    (e2,) = ev.run(claim="Contract covers this invoice",
                   source_url="https://contracts.example.com/ACME-2024-118",
                   content="MSA ACME-2024-118 active through 2026-12-31.",
                   collected_at="")
    bundle, root, _ = opl.OplEvidenceCollector().run(
        evidence_1=e1, evidence_2=e2, max_age_days=90, require_source=True)
    return bundle, root


def seal_and_write(ledger, task, th, bundle, root, key_path="",
                   strict_task=None, strict_evid=None, output=None,
                   strict_output=""):
    pol = core.evaluate_policy(dict(opl.DEFAULT_POLICY), task, bundle)
    appr, _, _ = opl.OplHumanApprovalGate().run(
        task=task, bundle=bundle, decision="APPROVED", approver="m.ibrahim",
        note="", strict_expected_task_hash=strict_task if strict_task is not None else th,
        strict_expected_evidence_root=strict_evid if strict_evid is not None else root,
        strict_expected_output_hash=strict_output, output=output)
    record, verdict, rh, _ = opl.OplDecisionSealer().run(
        task=task, bundle=bundle, policy_result=pol, approval=appr,
        ledger_path=ledger, hmac_key_path=key_path, output=output)
    opl.OplAuditLedgerWriter().run(record=record, ledger_path=ledger)
    return record, verdict


def expected(folder, lines):
    with open(os.path.join(folder, "expected.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main(out_dir=None):
    out = out_dir or os.path.join(ROOT, "examples", "tamper_pack")
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    key_path = os.path.join(out, "demo_key_correct_PUBLIC.txt")
    wrong_path = os.path.join(out, "demo_key_wrong_PUBLIC.txt")
    with open(key_path, "wb") as f:
        f.write(DEMO_KEY_CORRECT)
    with open(wrong_path, "wb") as f:
        f.write(DEMO_KEY_WRONG)

    # 01: clean signed ledger + passport.
    d1 = os.path.join(out, "01_clean")
    os.makedirs(d1)
    ledger1 = os.path.join(d1, "ledger.jsonl")
    t1, th1 = make_task(1840.00)
    b1, r1 = make_bundle()
    rec1, v1 = seal_and_write(ledger1, t1, th1, b1, r1, key_path=key_path)
    t2, th2 = make_task(420.00)
    b2, r2 = make_bundle()
    rec2, v2 = seal_and_write(ledger1, t2, th2, b2, r2, key_path=key_path)
    assert v1 == v2 == "APPROVED"
    passport = core.build_passport(ledger1, None)
    with open(os.path.join(d1, "passport.json"), "w", encoding="utf-8") as f:
        json.dump(passport, f, ensure_ascii=False, indent=2)
    expected(d1, [
        "python3 oplogica_core.py verify 01_clean/ledger.jsonl "
        "demo_key_correct_PUBLIC.txt",
        "-> CHAIN VALID | records=2 | signatures_checked=2 (exit 0)",
        "python3 oplogica_core.py verify-passport 01_clean/passport.json "
        "demo_key_correct_PUBLIC.txt",
        "-> PASSPORT VALID (exit 0)",
    ])

    # 02: in-place tamper of the clean ledger.
    d2 = os.path.join(out, "02_ledger_tampered")
    os.makedirs(d2)
    ledger2 = os.path.join(d2, "ledger.jsonl")
    with open(ledger1, "r", encoding="utf-8") as f:
        lines = f.readlines()
    bad = json.loads(lines[0])
    bad["task"]["amount"] = 999999.99
    lines[0] = json.dumps(bad, ensure_ascii=False) + "\n"
    with open(ledger2, "w", encoding="utf-8") as f:
        f.writelines(lines)
    expected(d2, [
        "python3 oplogica_core.py verify 02_ledger_tampered/ledger.jsonl",
        "-> CHAIN INVALID with HASH_MISMATCH on record[0] (exit 1)",
    ])

    # 03: wrong key against the clean ledger.
    d3 = os.path.join(out, "03_wrong_key")
    os.makedirs(d3)
    shutil.copy(ledger1, os.path.join(d3, "ledger.jsonl"))
    expected(d3, [
        "python3 oplogica_core.py verify 03_wrong_key/ledger.jsonl "
        "demo_key_wrong_PUBLIC.txt",
        "-> CHAIN INVALID with SIGNATURE_INVALID on both records (exit 1)",
    ])

    # 04: evidence changed after review.
    d4 = os.path.join(out, "04_changed_evidence")
    os.makedirs(d4)
    ledger4 = os.path.join(d4, "ledger.jsonl")
    t4, th4 = make_task()
    _, root_reviewed = make_bundle(status="open")
    changed_bundle, root_changed = make_bundle(status="VOID")
    assert root_reviewed != root_changed
    rec4, v4 = seal_and_write(ledger4, t4, th4, changed_bundle, root_changed,
                              strict_task=th4, strict_evid=root_reviewed)
    assert v4 == "BLOCKED"
    assert "EVIDENCE_BINDING_MISMATCH" in rec4["verdict"]["reasons"]
    expected(d4, [
        "python3 oplogica_core.py verify 04_changed_evidence/ledger.jsonl",
        "-> CHAIN VALID (the blocked decision is itself a sealed record)",
        "record verdict: BLOCKED, reasons include EVIDENCE_BINDING_MISMATCH",
    ])

    # 05: task changed after review.
    d5 = os.path.join(out, "05_changed_task")
    os.makedirs(d5)
    ledger5 = os.path.join(d5, "ledger.jsonl")
    reviewed_task, reviewed_th = make_task(1840.00)
    changed_task, changed_th = make_task(9999.00)
    b5, r5 = make_bundle()
    rec5, v5 = seal_and_write(ledger5, changed_task, changed_th, b5, r5,
                              strict_task=reviewed_th, strict_evid=r5)
    assert v5 == "BLOCKED"
    assert "TASK_BINDING_MISMATCH" in rec5["verdict"]["reasons"] or \
        any(x.startswith("POLICY_FAILED") for x in rec5["verdict"]["reasons"])
    expected(d5, [
        "python3 oplogica_core.py verify 05_changed_task/ledger.jsonl",
        "-> CHAIN VALID (the blocked decision is itself a sealed record)",
        "record verdict: BLOCKED, reasons include TASK_BINDING_MISMATCH",
    ])

    # 06: output changed after review.
    d6 = os.path.join(out, "06_changed_output")
    os.makedirs(d6)
    ledger6 = os.path.join(d6, "ledger.jsonl")
    t6, th6 = make_task()
    b6, r6 = make_bundle()
    binder = opl.OplOutputBinder()
    reviewed_out, reviewed_hash, _ = binder.run(
        text_artifact="PAY Acme Cloud 1840.00 USD ref INV-2291",
        artifact_path="")
    changed_out, changed_hash, _ = binder.run(
        text_artifact="PAY Acme Cloud 1840.00 USD ref INV-9999",
        artifact_path="")
    assert reviewed_hash != changed_hash
    rec6, v6 = seal_and_write(ledger6, t6, th6, b6, r6,
                              strict_task=th6, strict_evid=r6,
                              output=changed_out,
                              strict_output=reviewed_hash)
    assert v6 == "BLOCKED"
    assert "OUTPUT_BINDING_MISMATCH" in rec6["verdict"]["reasons"]
    expected(d6, [
        "python3 oplogica_core.py verify 06_changed_output/ledger.jsonl",
        "-> CHAIN VALID (the blocked decision is itself a sealed record)",
        "record verdict: BLOCKED, reasons include OUTPUT_BINDING_MISMATCH",
    ])

    with open(os.path.join(out, "README.md"), "w", encoding="utf-8") as f:
        f.write("""# Tamper demonstration pack

Six scripted scenarios showing exactly what the verifier catches. Each
folder contains the artifacts and an expected.txt with the command to run
and the result to expect. Regenerate everything with:

    python3 tools/build_tamper_pack.py

The two key files are PUBLIC demonstration keys, shipped on purpose so the
signature scenarios are reproducible. Never use them for real records.

Note the difference between the two failure families: scenarios 02 and 03
are attacks on the LEDGER (the file no longer verifies). Scenarios 04, 05,
and 06 are attacks on the APPROVAL (the ledger verifies cleanly, and what
it faithfully records is a BLOCKED decision with the exact binding reason).
Blocking produces evidence, not silence.

Scope: Tamper-evident record. Integrity is not truth.
""")
    print("Tamper pack written to %s (6 scenarios)" % out)
    return out


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
