# ZCC Sovereign Release Authority (`invariantzkaedi/zcc-release-authority`)

## Overview
This repository serves as the **independent, external release authority** for the [ZCC Bootstrap Compiler](https://github.com/invariantzkaedi/zcc-bootstrap-compiler).

In accordance with **Rule ZCC-EF-0 (Independent Verification Authority)**:
> **NO COMPONENT MAY CERTIFY ITS OWN CORRECTNESS USING EVIDENCE OR VERDICTS THAT IT CAN FABRICATE, MODIFY, REPLACE, OR CONTROL WITHOUT INDEPENDENT VERIFICATION.**

## Threat Model & Security Boundaries
1. **Producer Isolation:** The compiler repository (`zcc-bootstrap-compiler`) is an untrusted producer. A compromised commit in the producer tree (even one modifying all internal verifiers, policies, and workflows) has zero permission to authorize its own release.
2. **Untrusted Data Bundles:** The authority treats all inputs from the compiler repository as untrusted data (`untrusted_evidence_bundle.tar.gz`), extracting files safely without path traversals or symlinks.
3. **Zero Script Execution:** The authority verifier operates in a data-only mode, computing SHA-256 digests and evaluating raw byte equality directly. It never imports, evals, or executes scripts originating from the producer repository.
4. **Pinned Revisions:** Releases are certified against an externally approved authority commit SHA and cryptographic policy digest.

## Architecture
- `sovereign_release_policy.json`: Authoritative gate specifications, byte-equality invariants, and double-stage hash rules.
- `sovereign_release_verifier.py`: Independent, standalone evaluator.
- `.github/workflows/adjudicate-release.yml`: Authority-governed release adjudication runner.
