# Release Notes

## v1.0.0 (2026-06-12): Initial Public Release

First public release of the Oplogica ComfyUI Extension, an open-source
node pack for approval-bound decision records in ComfyUI. This is an
experimental technical release.

### What is included

* **10 implemented nodes** across six layers: Task Input, Evidence Item,
  Evidence Collector, Policy Check, Human Approval Gate, Decision Sealer,
  Chain Validator, Audit Ledger Writer, Decision Card Renderer, and Text
  Display.
* **Strict task-and-evidence approval binding.** The Human Approval Gate
  enforces both `strict_expected_task_hash` and
  `strict_expected_evidence_root` against the current task and evidence
  bundle. A task change after review yields `TASK_BINDING_MISMATCH`, an
  evidence change yields `EVIDENCE_BINDING_MISMATCH`, both yield
  `APPROVAL_BINDING_MISMATCH`, and a missing approver identity yields
  `NO_APPROVER_IDENTITY`.
* **Evidence Merkle root binding.** The bundle root is computed over
  sorted evidence item hashes: it identifies the evidence set independent
  of wiring order, and changes if any item's content, claim, source, or
  timestamp changes.
* **Sealed decision records.** Canonical-JSON records with SHA-256 record
  hashes, the bound and current task hashes, the bound and current
  evidence roots, binding mode, effective decision, downgrade reason, and
  explicit machine-readable reason codes. The Decision Sealer re-verifies
  the bound hashes against the task and bundle it actually seals.
* **Hash-chained local JSONL ledger.** Append-only records with
  previous-hash chaining, duplicate skipping, and chain validation through
  a node and a standalone CLI.
* **Stale ledger tail safety fix** (validated from the internal v0.2.1
  build). The Sealer, Writer, and Validator force re-execution on every
  queue, so the previous-record hash is always read from the ledger file
  as it exists at run time. A renamed, deleted, replaced, or emptied
  ledger yields a fresh chain start at GENESIS.
* **Append-time current-tail verification.** Before writing, the ledger
  layer re-derives the actual tail from the file. A record sealed against
  a ledger state that no longer exists is rejected with
  `STALE_PREV_REJECTED` instead of written, so a stale record cannot
  plant a chain break.
* **HMAC signing and CLI verification.** Optional HMAC-SHA256 signatures
  from a local key file; `python3 oplogica_core.py verify <ledger> [key]`
  recomputes every hash, chain link, and signature with exit code 0 on a
  valid chain.
* **Decision card renderer.** 1200x675 cards showing the verdict, task,
  evidence root, policy result, bound approval, binding mode, chain
  hashes, and the scope statement: Tamper-evident record. Integrity is
  not truth.
* **Generated demo workflow.** `workflows/oplogica_payment_demo.json` is
  generated from the node definitions and ships safe: decision PENDING,
  empty approver, empty strict fields (pass 1 of the two-pass flow).
* **Automated test suite.** 54 tests passing under both
  `python3 tests/test_oplogica.py` and `pytest tests/ -q`, including
  adversarial binding tests, seal-time swap detection, ledger-state
  regressions, CLI subprocess verification, and card rendering.

### Live validation

Validated in a Windows portable ComfyUI environment: custom node loading,
demo workflow loading, the two-pass approval flow, all three binding
mismatch blocks, ledger rename while ComfyUI remains running with the new
ledger starting from GENESIS, continued chaining after additional runs,
HMAC verification with the correct key, HMAC rejection with the wrong key,
and manual tamper detection through `HASH_MISMATCH`. This is one
environment, not a compatibility matrix.

### Known limitations

No mid-run pause in ComfyUI (two-pass flow instead); no conditional
branching (blocking is node semantics, every run seals a record); HMAC is
integrity plus key possession, not non-repudiation; approver identity is
asserted text, not authenticated; the policy engine is declarative and
deterministic only; the ledger is tamper-evident, not tamper-proof; live
validation covers one environment with no CI across ComfyUI versions yet;
frontend cosmetics depend on ComfyUI's unversioned extension API; the
classic node API is targeted; strict binding is opt-in per run. See
README.md for the full list with details.

---

## Internal development history (pre-release builds)

These versions were internal builds and were never published.

* **v0.2.1:** Fixed stale chain tail state after ledger rename or delete
  at runtime (Sealer re-execution via IS_CHANGED plus append-time
  current-tail verification with `STALE_PREV_REJECTED`). Added five
  ledger-state regression tests (suite: 49 to 54). First live ComfyUI
  behavior validation.
* **v0.2.0:** Closed the critical binding gap: strict approval binding
  extended from task hash only to both task hash and evidence Merkle
  root, with explicit reason codes, seal-time binding re-verification,
  order-normalized evidence roots, a safe PENDING default workflow,
  claim-safe documentation, Apache-2.0 LICENSE and NOTICE, and an
  expanded suite (32 to 49 tests).
* **v0.1.0:** Initial internal build: 10 nodes across 6 layers,
  task-hash-bound two-pass approval, declarative policy engine,
  hash-chained JSONL ledger, chain validator, decision card renderer,
  generated demo workflow, 32 tests.
