# Oplogica Visual Decision Operating System
## Full Node Catalog and Strategic Architecture

Pack version 1.0.0. Status legend: **MVP** = implemented and tested now,
**P2** = Phase 2 (specified only, NOT implemented), **P3** = Phase 3
(specified only, NOT implemented).

Hard boundary: exactly 10 nodes are implemented in this package (the rows
marked MVP). Every other row in this document is a design specification
for future work. Nothing marked P2 or P3 exists as code today, and no
public claim should describe it as existing.

ComfyUI classification legend:
**A** = visual-only (none in this catalog; decorative nodes were explicitly
rejected), **B** = functional Python node (classic API, no frontend code),
**C** = full extension (needs custom JavaScript).

---

## Layer architecture

Six operational layers plus one utility group. Data flows left to right:
facts enter, evidence is structured and hashed, a human binds an approval to
exactly what they reviewed, policy verifies deterministically, the trust
layer seals and chains, and the action layer records and publishes.

Custom graph types carry structured dicts between layers:
`OPL_TASK`, `OPL_EVIDENCE`, `OPL_BUNDLE`, `OPL_CHECK`, `OPL_APPROVAL`,
`OPL_RECORD`. All are JSON-serializable; nothing hides in object state.

## Color system

Premium dark theme, one color family per layer, applied automatically by
`web/oplogica.js` (header color, body color):

| Layer | Header | Body | Rationale |
|---|---|---|---|
| 1 Input | #475569 | #141a22 | neutral slate: raw, unverified material |
| 2 Evidence | #0369A1 | #0b2231 | deep blue: structured fact |
| 3 Approval | #B45309 | #2a1a07 | amber: human attention required |
| 4 Verification | #7C3AED | #221038 | violet: machine scrutiny |
| 5 Trust | #059669 | #062a21 | emerald: cryptographic seal |
| 6 Action | #6B7280 | #1a1f29 | graphite, white text: consequence |
| Utility | #334155 | #10151c | recedes behind the six layers |

Verdict colors on rendered cards: APPROVED #10B981, BLOCKED #EF4444,
PENDING #F59E0B, accent #38BDF8, background #0B0F14. The canvas itself reads
as a mission-control board: cool dark field, six colored bands (the workflow
ships with matching group frames), one loud verdict.

---

## Layer 1: INPUT (slate)

| Node | Purpose | I/O | Class | Status |
|---|---|---|---|---|
| Task Input | Normalizes a requested action (actor, action_type, amount, payload) and computes the semantic `task_hash` everything downstream binds to | widgets in; OPL_TASK + task_hash out | B | MVP |
| Evidence Item | One claim + source reference + raw content; content is hashed downstream, never embedded in records | widgets in; OPL_EVIDENCE out | B | MVP |
| Agent Request Adapter | Parses a JSON request emitted by an external agent (LangChain, CrewAI, raw API) into OPL_TASK; rejects malformed payloads with a parse record | STRING in; OPL_TASK out | B | P2 |
| Document Input | Loads a file, captures SHA-256 + metadata as evidence | path widget; OPL_EVIDENCE out | B | P2 |
| API Request Input | Fetches a URL at run time, records body hash + headers + retrieval time as evidence | widgets; OPL_EVIDENCE out | B | P2 |
| Evidence Package Input | Imports a previously exported, sealed evidence bundle and re-verifies its Merkle root on import | path widget; OPL_BUNDLE out | B | P2 |
| Human Instruction | Free-text instruction wrapped as a task with actor_type=human | widgets; OPL_TASK out | B | P2 |
| Context Package | Named contextual facts (environment, jurisdiction, account tier) hashed into the record | widgets; OPL_CONTEXT out | B | P3 |

## Layer 2: EVIDENCE (blue)

| Node | Purpose | I/O | Class | Status |
|---|---|---|---|---|
| Evidence Collector | Aggregates up to 4 items: per-item SHA-256, completeness, freshness, source presence, dedupe, Merkle root over SORTED item hashes (order-independent set identity; any content, claim, source, or timestamp change alters the root) | OPL_EVIDENCE x4 in; OPL_BUNDLE + root + report out | B | MVP (folds the 4 nodes below) |
| Evidence Completeness Check | Standalone: required fields present per item, gap list | OPL_BUNDLE in; OPL_CHECK out | B | P2 |
| Evidence Freshness Check | Standalone: age vs threshold per item | OPL_BUNDLE in; OPL_CHECK out | B | P2 |
| Reference Integrity Check | Re-fetches each source URL, compares current content hash to the hash captured at collection time: detects evidence rot | OPL_BUNDLE in; OPL_CHECK out | B | P2 |
| Source Registry | Declares trusted source patterns with tiers (official, internal, public) | widgets; OPL_REGISTRY out | B | P2 |
| Source Verifier | Scores each item's source against the registry | OPL_BUNDLE + OPL_REGISTRY in; OPL_CHECK out | B | P2 |
| Conflict Discovery | Flags numeric and date disagreements between items referencing the same field | OPL_BUNDLE in; OPL_CHECK out | B | P2 |
| Contradiction Scanner | NLI-based pairwise entailment/contradiction over claims (optional model download; degrades to lexical heuristics) | OPL_BUNDLE in; OPL_CHECK out | B | P2 |
| Trust Score Builder | Aggregates evidence checks into a 0-100 score with stated weights; the weights are recorded, the score never auto-approves | OPL_CHECK list in; OPL_SCORE out | B | P3 |

## Layer 3: APPROVAL (amber)

| Node | Purpose | I/O | Class | Status |
|---|---|---|---|---|
| Human Approval Gate | Task-and-evidence-bound approval: strict mode enforces BOTH strict_expected_task_hash and strict_expected_evidence_root against the current task and bundle; APPROVED is downgraded with TASK_BINDING_MISMATCH, EVIDENCE_BINDING_MISMATCH, APPROVAL_BINDING_MISMATCH, or NO_APPROVER_IDENTITY; bundle input is required | OPL_TASK + OPL_BUNDLE in; OPL_APPROVAL out | B | MVP |
| Blocking Approval Gate | True mid-run pause: frontend dialog + threading.Event (the technique proven by community "image chooser" nodes); times out to PENDING | same as above | C | P2 |
| Dual Approval Gate | Requires two distinct approver identities; same person twice = downgrade | 2x OPL_APPROVAL in; OPL_APPROVAL out | B | P2 |
| Risk Threshold Gate | Routes by amount/risk_hint: below threshold passes with auto-record, above requires the human gate | OPL_TASK in; OPL_CHECK out | B | P2 |
| Sensitive Action Gate | Pattern list (delete, transfer.external, credentials) that forces human review regardless of other signals | OPL_TASK in; OPL_CHECK out | B | P2 (MVP: inside policy engine) |
| Escalation Gate | On REJECTED or repeated PENDING, emits an escalation record addressed to a named role | OPL_APPROVAL in; OPL_APPROVAL out | B | P3 |
| Exception Review | Records a policy exception: which rule, who accepted the risk, expiry date; sealed like any decision | widgets + OPL_CHECK in; OPL_APPROVAL out | B | P3 |

## Layer 4: VERIFICATION (violet)

| Node | Purpose | I/O | Class | Status |
|---|---|---|---|---|
| Policy Check | Declarative JSON policy: allowed actions, monetary limits, evidence minimums, freshness, sensitive patterns; one structured result per rule, policy hash recorded | OPL_TASK + OPL_BUNDLE in; OPL_CHECK out | B | MVP |
| Evidence Integrity Check | Recomputes the bundle Merkle root from item hashes; any drift since collection fails | OPL_BUNDLE in; OPL_CHECK out | B | P2 (MVP: inside Sealer summary + tests) |
| Action Verification | Compares an executed action's reported parameters to the approved task: catches "approved X, executed Y" | OPL_TASK + OPL_RESULT in; OPL_CHECK out | B | P2 |
| Workflow Verification | Verifies the graph itself: required gates present and connected on the path to the Sealer | graph introspection; OPL_CHECK out | B | P2 |
| Decision Consistency Check | Compares the verdict to similar historical records in the ledger; flags deviations for review (flags, never blocks alone) | OPL_RECORD + ledger in; OPL_CHECK out | B | P3 |
| Reasoning Verification | Checks stated reasoning steps against evidence items (NLI entailment); marks unsupported steps | OPL_TASK + OPL_BUNDLE in; OPL_CHECK out | B | P3 |

## Layer 5: TRUST (emerald)

| Node | Purpose | I/O | Class | Status |
|---|---|---|---|---|
| Decision Sealer | Computes the verdict (APPROVED only if policy passed AND effective approval APPROVED AND the approval's bound task hash and bound evidence root match the sealed task and bundle AND an approver identity exists; else BLOCKED with explicit reason codes), assembles the record, canonical-JSON SHA-256 record hash, chains to ledger tail, optional HMAC | task+bundle+check+approval in; OPL_RECORD + verdict + hash + json out | B | MVP (folds Hash Generator, Record Builder, Signature Generator) |
| Chain Validator | Re-reads the ledger; recomputes every hash, every prev-link, every HMAC; reports HASH_MISMATCH / CHAIN_BREAK / SIGNATURE_INVALID per record | path widgets; valid + report + length out | B | MVP |
| Hash Generator | Standalone canonical-JSON SHA-256 of any payload | any in; STRING out | B | P2 |
| Merkle Builder | Standalone Merkle root over arbitrary hash lists | list in; STRING out | B | P2 |
| Signature Generator (Ed25519) | Asymmetric signing: private key signs, anyone verifies with the public key; actual non-repudiation | OPL_RECORD in; OPL_RECORD out | B | P2 |
| Trust Root Generator | Periodic checkpoint record summarizing ledger state (count, tail hash) for external anchoring | ledger in; OPL_RECORD out | B | P3 |
| Tamper Detection Monitor | Watches a ledger file and alerts on any historical mutation between runs | path widget; report out | B | P3 |

## Layer 6: ACTION (graphite/white)

| Node | Purpose | I/O | Class | Status |
|---|---|---|---|---|
| Audit Ledger Writer | Appends the sealed record to append-only JSONL; idempotent against immediate duplicates | OPL_RECORD in; path + position + hash + status out | B | MVP |
| Decision Card Renderer | 1200x675 dark card (verdict pill, task, evidence root, policy, bound approval, chain, scope line); the LinkedIn asset is generated by the system itself | OPL_RECORD in; IMAGE out | B | MVP |
| Guarded Executor | Executes a webhook/command ONLY if the connected record's verdict is APPROVED; refusal emits a refusal record | OPL_RECORD in; OPL_RESULT out | B | P2 |
| Request More Evidence | Emits a structured evidence request (which checks failed, what is needed) as a record | OPL_CHECK in; OPL_RECORD out | B | P2 |
| Decision Record Publisher | Exports the record as JSON + card + verification instructions; optional POST to the OpLogica Verify REST API | OPL_RECORD in; path out | B | P3 |
| Notification Dispatcher | Sends the card + verdict to Slack/email on seal | OPL_RECORD in; status out | B | P3 |

## Utility

| Node | Purpose | Class | Status |
|---|---|---|---|
| Text Display | Read-only inline panel showing any report output (the gate's task_hash, validator results) | C (small JS) | MVP |
| Record Inspector | Pretty, foldable record viewer | C | P2 |

Catalog total: 30 nodes designed; 10 implemented in the MVP. The MVP folds
Completeness + Freshness + Merkle into the Collector and Hash + Record +
Signature into the Sealer so a complete, honest demo fits in one screen.

---

## Ten demonstration scenarios

Node flows use MVP nodes unless marked (P2). Every scenario ends with a
sealed record and a rendered card; that is the point.

1. **AI agent requests a vendor payment** (the shipped demo).
   Task Input (ai_agent, payment.vendor, 1840 USD) -> 2x Evidence Item
   (invoice, contract) -> Collector -> Policy Check + Human Approval Gate
   (strict, m.ibrahim) -> Sealer -> Ledger Writer -> Card + Validator.
   Outcome: APPROVED card, chained record.

2. **AI approves an expense, a human does not.**
   Same graph; the agent's request is within policy (8/8 rules pass) but the
   reviewer sets REJECTED. Outcome: BLOCKED card with reason
   APPROVAL_REJECTED, policy-passed shown in green on the same card. The
   card itself argues "policy compliance is not permission."

3. **Insurance certificate (COI) issuance.**
   Task Input (issue.certificate) -> Evidence Items (policy document hash,
   broker license, coverage table) -> Collector -> Policy Check (allowed
   action, evidence min 3) -> Gate (broker identity) -> Sealer -> Writer ->
   Card. Ties directly to the Oplogica COI Reviewable Workflow Pack.

4. **Document approval with tamper catch.**
   Pass 1: reviewer reads the document evidence, copies task_hash. Someone
   edits the payload before pass 2. Gate downgrades: TASK_BINDING_MISMATCH;
   if the evidence is what changed, EVIDENCE_BINDING_MISMATCH; if both,
   APPROVAL_BINDING_MISMATCH.
   Outcome: BLOCKED card proving the approval refused to transfer to
   content the approver never saw.

5. **Vendor onboarding.**
   Task (vendor.onboard) -> Evidence (registry extract, tax ID, bank letter)
   -> Collector -> Policy (min 3 items, all sourced) -> Dual Approval (P2;
   MVP: single gate) -> Sealer -> Writer -> Card.

6. **Contract review.**
   Document Input (P2; MVP: Evidence Item with the contract hash) ->
   Collector -> Policy (amount = contract value vs authority limit) -> Gate
   -> Sealer. Card shows the contract hash the approval is bound to.

7. **Policy exception request.**
   Task exceeds max_amount -> Policy FAILS -> run seals BLOCKED
   (POLICY_FAILED:amount_within_limit) -> second run with Exception Review
   (P3; MVP: gate note documents the accepted risk, record preserves the
   failed rule verbatim). The exception is itself an auditable record.

8. **AI recommendation review.**
   Agent Request Adapter (P2; MVP: Task Input with the model's proposal in
   payload_json) -> Evidence Items (the sources the model cited) ->
   Collector -> Gate. Outcome: the human approves the recommendation bound
   to the exact evidence set, or it stays PENDING.

9. **High-risk deployment approval.**
   Task (deploy.production, risk_hint=critical) -> sensitive pattern scan
   forces requires_human=true -> Gate strict mode -> Sealer -> Validator.
   Demo line: "no path to APPROVED exists without a named human."

10. **Customer refund authorization.**
    Task (refund.customer, 240 USD) -> Evidence (original charge, complaint
    ticket) -> Policy (refund.customer allowed, under limit) -> Gate ->
    Sealer -> Card. Small, relatable, runs in 30 seconds on video.

## Viral potential ranking (LinkedIn)

1. **The BLOCKED red card (scenario 2 or 9).** A loud red BLOCKED panel
   with "policy 8/8 passed" next to "human REJECTED" is a one-image
   argument. It inverts the genre: every other AI demo shows the machine
   succeeding; this shows the system refusing, and the refusal producing
   evidence. Caption writes itself: "My AI passed every check. It still
   did not get to act."
2. **Tampered-ledger detection (a 20-second screen recording).** Open the
   JSONL, change one digit of one amount, re-queue, the Chain Validator
   prints HASH_MISMATCH on the exact record. Tangible cryptography beats
   abstract cryptography. Strong with the compliance and audit crowd.
3. **The binding mismatch catch (scenario 4).** "I approved the task,
   someone changed it, my approval refused to follow." This is the novel
   primitive (evidence-bound approval) demonstrated in one run. Slightly
   more setup to explain than 1 and 2, hence third.
4. **Two-pass approval flow (scenario 1 as a video).** Calm, end-to-end,
   credible; converts interest into "how do I run this," lower raw reach.
5. **COI issuance (scenario 3).** Niche reach, highest commercial intent;
   directly feeds the brokerage product conversation.

## Strategic differentiation

The honest competitive read first: visual workflow tools are crowded
(n8n, Flowise, LangFlow), agent orchestration is crowded (LangGraph, CrewAI,
AutoGen), and the integrity layer is commoditized (Sigstore, C2PA, in-toto).
Oplogica should not compete on orchestration and does not.

Where this system is actually different:

1. **The record is the product.** Orchestrators treat logs as exhaust; here
   every run's primary output is a sealed, chained, independently
   verifiable decision record. The graph exists to produce the record.
2. **Evidence-bound approval as a first-class visual primitive.** No
   mainstream tool binds a human approval cryptographically to the task
   hash plus the evidence Merkle root the human actually reviewed, with
   automatic downgrade on drift. LangGraph's human-in-the-loop interrupts
   pause execution; they do not bind the approval to reviewed content.
3. **Blocking generates evidence.** In n8n a failed condition is a dead
   branch. Here a BLOCKED outcome seals a record with reason codes; the
   refusal is auditable. Approval-as-absence becomes approval-as-artifact.
4. **The receipt is the render.** The system's own output (the decision
   card) is the marketing asset. Demos do not screenshot the tool; they
   publish what the tool produced.
5. **Stated epistemic limits on the artifact itself.** Every card carries
   "Tamper-evident record. Integrity is not truth." Competitors overclaim;
   the scope line is the brand.
6. **A liftable core.** `oplogica_core.py` has zero ComfyUI imports. The
   same seal/verify code becomes the OpLogica Verify REST API (Phase 3):
   the ComfyUI pack is the visible demo of an infrastructure layer, not
   the product ceiling.

## Risks

1. **Audience mismatch.** ComfyUI's community is image-generation focused.
   Mitigation: ComfyUI is the rendering stage for LinkedIn demos, not the
   distribution channel; the audience is on LinkedIn, not the registry.
2. **"Security theater" accusation.** Asserted approver identity, local
   HMAC. Mitigation: the limitations section, the scope line on every
   card, and reason codes; underclaim everywhere.
3. **Frontend API drift** breaks colors/text panel. Mitigation: pure
   cosmetic dependency; functionality is backend-only.
4. **HMAC misread as digital signatures.** Mitigation: cards print
   "unsigned / HMAC" state explicitly; Ed25519 is named Phase 2.
5. **Scope creep into orchestration.** Pressure to add executors, loops,
   integrations until it becomes a worse n8n. Mitigation: the executor
   stays a thin guarded webhook; orchestration is explicitly out of scope.
6. **GPL-3 contamination concern** for commercial reuse. Mitigation: the
   core is import-clean and separable today.

## Recommended implementation order

1. Core seal/verify + tests (done).
2. The 10 MVP nodes + demo workflow + cards (done).
3. Manual validation inside a live ComfyUI instance; record the three
   top-ranked demo videos.
4. P2 trust upgrades: Ed25519, Reference Integrity Check, Guarded Executor.
5. P2 blocking approval gate (frontend event technique) once the two-pass
   story has shipped publicly; it becomes the "v2 moment."
6. P3 REST bridge to OpLogica Verify; the ComfyUI pack becomes a client.
