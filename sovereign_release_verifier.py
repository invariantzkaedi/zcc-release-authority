#!/usr/bin/env python3
"""
ZCC OMEGA V4-M5 — Sovereign Release Verifier (Rule ZCC-EF-0 Compliance)
=============================================================================
Independent release authority that enforces externally maintained trust policies
against raw stage artifacts and verification receipts. Operates exclusively
on untrusted data bundles without importing or executing producer code.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

EXIT_OK = 0
EXIT_POLICY_ERROR = 10
EXIT_BYTE_MISMATCH = 11
EXIT_FORGERY_DETECTED = 12
EXIT_MISSING_ARTIFACT = 13

def reject(msg, code):
    print(f"SOVEREIGN VERIFIER REJECT: {msg}", file=sys.stderr)
    sys.exit(code)

def safe_extract_bundle(bundle_path: Path, dest_dir: Path) -> Path:
    """
    Safely extract untrusted evidence tarball. Enforces strict path traversal,
    symlink ban, allowlisted names, and volume limits.
    """
    if not bundle_path.is_file():
        reject(f"Evidence bundle not found: {bundle_path}", EXIT_MISSING_ARTIFACT)
    
    dest_dir.mkdir(parents=True, exist_ok=True)
    total_size = 0
    with tarfile.open(bundle_path, "r:*") as tar:
        for member in tar.getmembers():
            # 1. Path traversal prohibition
            if member.name.startswith("/") or ".." in member.name.split("/"):
                reject(f"ARCHIVE SECURITY VIOLATION: Path traversal in member '{member.name}'", EXIT_POLICY_ERROR)
            # 2. Symlink / Hardlink Ban
            if not member.isreg():
                reject(f"ARCHIVE SECURITY VIOLATION: Non-regular file member '{member.name}'", EXIT_POLICY_ERROR)
            # 3. Allowlist check
            norm_name = os.path.normpath(member.name).replace("\\", "/")
            is_allowed = (
                norm_name in {
                    "stage2.s", "stage3.s", "stage2.o", "stage3.o",
                    "stage2.bin.norm", "stage3.bin.norm", "stage2.bin", "stage3.bin",
                    "meta_verification_receipt.json", "meta_verification.log", "provenance.json"
                }
                or norm_name.startswith("evidence/")
                or norm_name.startswith("scripts/")
                or norm_name.startswith("tools/")
            )
            if not is_allowed:
                reject(f"ARCHIVE SECURITY VIOLATION: Disallowed member '{member.name}' in bundle", EXIT_POLICY_ERROR)
            # 4. Size limits
            if member.size > 50 * 1024 * 1024:
                reject(f"ARCHIVE SECURITY VIOLATION: Member '{member.name}' exceeds 50MB ({member.size} bytes)", EXIT_POLICY_ERROR)
            total_size += member.size
            if total_size > 250 * 1024 * 1024:
                reject(f"ARCHIVE SECURITY VIOLATION: Total bundle uncompressed size exceeds 250MB", EXIT_POLICY_ERROR)
        
        tar.extractall(path=dest_dir)
    return dest_dir

def main():
    parser = argparse.ArgumentParser(description="ZCC OMEGA V4-M5 Sovereign Release Verifier")
    parser.add_argument("--policy", required=True, help="Path to externally maintained sovereign trust policy JSON")
    parser.add_argument("--evidence", default=None, help="Path to directory containing raw artifacts")
    parser.add_argument("--bundle", default=None, help="Path to untrusted evidence bundle tar archive")
    parser.add_argument("--receipt", default=None, help="Optional explicit path to receipt JSON")
    parser.add_argument("--expected-commit", default=None, help="Mandatory expected commit SHA from trusted caller context")
    parser.add_argument("--repo", default=None, help="Optional path to repository root under evaluation")
    parser.add_argument("--log", default=None, help="Optional path to execution log to audit negative control execution proofs")
    parser.add_argument("--scratch-dir", default=None, help="Optional scratch directory for bundle extraction")
    args = parser.parse_args()

    policy_path = Path(args.policy).resolve()
    if not policy_path.is_file():
        reject(f"Policy file not found: {policy_path}", EXIT_POLICY_ERROR)

    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as e:
        reject(f"Malformed policy JSON: {e}", EXIT_POLICY_ERROR)

    # Invariant enforcement
    if policy.get("required_commit_binding") is False:
        reject("POLICY INTEGRITY VIOLATION (V4-06): Policy cannot disable required_commit_binding", EXIT_POLICY_ERROR)
    if policy.get("stage_identity", {}).get("require_direct_byte_equality") is False:
        reject("POLICY INTEGRITY VIOLATION (V4-06): Policy cannot disable require_direct_byte_equality", EXIT_POLICY_ERROR)
    if policy.get("negative_controls", {}).get("disallow_unconditional_pass") is False:
        reject("POLICY INTEGRITY VIOLATION (V4-06): Policy cannot allow unconditional pass in negative controls", EXIT_POLICY_ERROR)
    if policy.get("stage_identity", {}).get("require_double_stage_hash_recomputation") is False:
        reject("POLICY INTEGRITY VIOLATION (V4-06): Policy cannot disable require_double_stage_hash_recomputation", EXIT_POLICY_ERROR)

    # Resolve evidence directory
    extracted_tmp = None
    if args.bundle:
        bundle_path = Path(args.bundle).resolve()
        dest = Path(args.scratch_dir).resolve() if args.scratch_dir else Path("/tmp/zcc_extracted_bundle")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        evidence_dir = safe_extract_bundle(bundle_path, dest)
        extracted_tmp = dest
    elif args.evidence:
        evidence_dir = Path(args.evidence).resolve()
        if not evidence_dir.is_dir():
            reject(f"Evidence directory not found: {evidence_dir}", EXIT_MISSING_ARTIFACT)
    else:
        reject("Must specify either --evidence or --bundle", EXIT_POLICY_ERROR)

    # Resolve receipt
    if args.receipt:
        receipt_file = Path(args.receipt).resolve()
    elif (evidence_dir / "meta_verification_receipt.json").is_file():
        receipt_file = evidence_dir / "meta_verification_receipt.json"
    elif (evidence_dir.parent / "meta_verification_receipt.json").is_file():
        receipt_file = evidence_dir.parent / "meta_verification_receipt.json"
    elif Path("meta_verification_receipt.json").is_file():
        receipt_file = Path("meta_verification_receipt.json").resolve()
    else:
        reject(f"Receipt file missing in evidence dir or repo root", EXIT_MISSING_ARTIFACT)

    if not receipt_file.is_file():
        reject(f"Receipt file missing: {receipt_file}", EXIT_MISSING_ARTIFACT)
    if os.path.islink(receipt_file):
        reject(f"Receipt file must not be a symbolic link: {receipt_file}", EXIT_POLICY_ERROR)

    try:
        receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    except Exception as e:
        reject(f"Malformed receipt JSON: {e}", EXIT_POLICY_ERROR)

    # 1. Negative Control Integrity & Anti-Forgery (NC-21 Detection)
    neg_policy = policy.get("negative_controls", {})
    if neg_policy.get("disallow_unconditional_pass", True):
        forbidden_rcs = set(neg_policy.get("forbidden_gate_rc_values", [0]))
        required_codes = neg_policy.get("required_rejection_codes", {})
        neg_receipt = receipt.get("negative_controls", {})

        if not neg_receipt or len(neg_receipt) == 0:
            reject("NC-14 VIOLATION: Empty negative controls collection", EXIT_FORGERY_DETECTED)

        for name, expected_rc in required_codes.items():
            ctrl = neg_receipt.get(name)
            if not ctrl:
                reject(f"Missing required negative control '{name}' in receipt", EXIT_FORGERY_DETECTED)

            observed_rc = ctrl.get("gate_rc")
            if observed_rc in forbidden_rcs:
                reject(
                    f"CRITICAL FORGERY DETECTED (NC-21): negative control '{name}' reported gate_rc={observed_rc} "
                    f"(forbidden unconditional PASS)",
                    EXIT_FORGERY_DETECTED,
                )

            if observed_rc != expected_rc:
                reject(
                    f"CRITICAL FORGERY DETECTED: negative control '{name}' reported gate_rc={observed_rc}, expected {expected_rc}",
                    EXIT_FORGERY_DETECTED,
                )

    # 2. Stage Identity & Raw Disk Byte Equality
    stage_policy = policy.get("stage_identity", {})
    if stage_policy.get("require_direct_byte_equality", True):
        stage_pairs = stage_policy.get("required_stage_pairs", [])
        digests = receipt.get("digests", {})

        for pair in stage_pairs:
            fn2 = pair.get("stage2")
            fn3 = pair.get("stage3")
            
            # Find artifact in evidence_dir or evidence_dir/evidence/latest
            p2 = evidence_dir / fn2
            if not p2.is_file() and (evidence_dir / "evidence" / "latest" / fn2).is_file():
                p2 = evidence_dir / "evidence" / "latest" / fn2

            p3 = evidence_dir / fn3
            if not p3.is_file() and (evidence_dir / "evidence" / "latest" / fn3).is_file():
                p3 = evidence_dir / "evidence" / "latest" / fn3

            if not p2.is_file():
                reject(f"Required artifact '{fn2}' missing from evidence directory", EXIT_MISSING_ARTIFACT)
            if not p3.is_file():
                reject(f"Required artifact '{fn3}' missing from evidence directory", EXIT_MISSING_ARTIFACT)

            if os.path.islink(p2) or os.path.islink(p3):
                reject(f"Artifacts must not be symbolic links: {fn2} or {fn3}", EXIT_POLICY_ERROR)

            b2 = p2.read_bytes()
            b3 = p3.read_bytes()

            if b2 != b3:
                reject(f"RAW BYTE INEQUALITY: {fn2} and {fn3} bytes do not match", EXIT_BYTE_MISMATCH)

            sha2 = hashlib.sha256(b2).hexdigest()
            sha3 = hashlib.sha256(b3).hexdigest()

            if sha2 != sha3:
                reject(f"DIGEST MISMATCH: {fn2} ({sha2}) != {fn3} ({sha3})", EXIT_BYTE_MISMATCH)

            dkey = pair.get("digest_key") or pair.get("name")
            key2 = f"stage2_{dkey}"
            key3 = f"stage3_{dkey}"
            rec2 = digests.get(key2)
            rec3 = digests.get(key3)

            if not rec2:
                reject(f"RECEIPT INCOMPLETE (V4-03): Missing required digest field '{key2}' in receipt", EXIT_FORGERY_DETECTED)
            if not rec3:
                reject(f"RECEIPT INCOMPLETE (V4-03): Missing required digest field '{key3}' in receipt", EXIT_FORGERY_DETECTED)

            def is_valid_sha256(h):
                return isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h)

            if not is_valid_sha256(rec2):
                reject(f"MALFORMED DIGEST (V4-03): Field '{key2}' is not a valid 64-char hex SHA-256: '{rec2}'", EXIT_FORGERY_DETECTED)
            if not is_valid_sha256(rec3):
                reject(f"MALFORMED DIGEST (V4-03): Field '{key3}' is not a valid 64-char hex SHA-256: '{rec3}'", EXIT_FORGERY_DETECTED)

            if rec2.lower() != sha2.lower():
                reject(f"STALE DIGEST (V4-03): Recomputed {fn2} ({sha2}) != receipt ({rec2})", EXIT_BYTE_MISMATCH)
            if rec3.lower() != sha3.lower():
                reject(f"COUNTERFEIT STAGE 3 DIGEST (V4-03): Recomputed {fn3} ({sha3}) != receipt ({rec3})", EXIT_BYTE_MISMATCH)

    # 3. Cleanliness Enforcement
    clean_policy = policy.get("cleanliness", {})
    if clean_policy.get("require_workdir_cleaned", True):
        cleanup = receipt.get("cleanup", {})
        if not cleanup.get("harness_workdir_cleaned"):
            reject("Workdir cleanup was not verified (EF-03 violation)", EXIT_POLICY_ERROR)

    # 4. Lineage Binding
    if policy.get("required_commit_binding", True):
        if not args.expected_commit:
            reject("POLICY VIOLATION (V4-02): 'required_commit_binding' is true but --expected-commit was omitted.", EXIT_POLICY_ERROR)

        exp_commit = args.expected_commit.strip().lower()
        if len(exp_commit) != 40 or not all(c in "0123456789abcdef" for c in exp_commit):
            reject(f"MALFORMED INPUT (V4-02): --expected-commit must be a 40-character hex commit SHA: '{args.expected_commit}'", EXIT_POLICY_ERROR)

        prov = receipt.get("provenance", {})
        rec_commit = prov.get("git_commit")
        if not rec_commit:
            reject("LINEAGE VIOLATION (V4-02): Receipt is missing 'provenance.git_commit'", EXIT_POLICY_ERROR)

        if str(rec_commit).strip().lower() != exp_commit:
            reject(f"LINEAGE MISMATCH (V4-02): Receipt commit '{rec_commit}' does not match expected '{args.expected_commit}'", EXIT_POLICY_ERROR)

    # 5. Inert Adjudicator Script Integrity (V4-M5-03: Raw byte digest only, NO execution)
    adj_policy = policy.get("adjudicator_integrity", {})
    if adj_policy.get("require_adjudicator_hash_pinned", False) and args.repo:
        pinned = adj_policy.get("pinned_scripts", {})
        repo_root = Path(args.repo).resolve()

        for script_name, expected_sha in pinned.items():
            script_path = repo_root / script_name
            if not script_path.is_file():
                reject(f"MISSING ADJUDICATOR SCRIPT: {script_name} not found in repo", EXIT_POLICY_ERROR)
            
            actual_sha = hashlib.sha256(script_path.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                reject(f"ADJUDICATOR COMPROMISED (NC-21B / NC-25): Script '{script_name}' SHA-256 {actual_sha} != pinned {expected_sha}", EXIT_FORGERY_DETECTED)

    # 6. Negative Control Execution Proof Audit
    log_file = None
    if args.log:
        log_file = Path(args.log).resolve()
    elif (evidence_dir / "meta_verification.log").is_file():
        log_file = evidence_dir / "meta_verification.log"
    elif (evidence_dir.parent / "meta_verification.log").is_file():
        log_file = evidence_dir.parent / "meta_verification.log"
    elif Path("meta_verification.log").is_file():
        log_file = Path("meta_verification.log").resolve()

    if log_file and log_file.is_file():
        log_text = log_file.read_text(errors="replace")
        required_log_markers = [
            "FAIL: Assembly files diverged",
            "FAIL: Object files diverged",
            "FAIL: Binary files diverged post-normalization",
            "ALL NEGATIVE CONTROL GATES METICULOUSLY VERIFIED"
        ]
        for marker in required_log_markers:
            if marker not in log_text:
                reject(f"EXECUTION AUDIT FAILURE (V4-07): Execution log lacks verified negative control failure marker: '{marker}'", EXIT_FORGERY_DETECTED)

    print("SOVEREIGN RELEASE POLICY VERIFIED: PASS", file=sys.stdout)
    sys.exit(EXIT_OK)

if __name__ == "__main__":
    main()
