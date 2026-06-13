# Tamper demonstration pack

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
