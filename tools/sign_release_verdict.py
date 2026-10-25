#!/usr/bin/env python3
"""
🛡️ SOVEREIGN RELEASE AUTHORITY ED25519 VERDICT SIGNER
================================================================================
Signs the canonical sovereign release verdict using the authority Ed25519
private key. Ensures non-repudiation, tamper-proof lineage binding, and
asymmetric authorization per Rule ZCC-EF-0 and RFC 8032.
================================================================================
"""

import os
import sys
import json
import hashlib
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def load_private_key(key_path_str: str = None) -> ed25519.Ed25519PrivateKey:
    # 1. Direct path argument
    if key_path_str and Path(key_path_str).is_file():
        key_bytes = Path(key_path_str).read_bytes()
        return serialization.load_pem_private_key(key_bytes, password=None)

    # 2. Environment variable (PEM string or hex)
    env_key = os.environ.get("AUTHORITY_ED25519_PRIVATE_KEY", "").strip()
    if env_key:
        if "BEGIN PRIVATE KEY" in env_key or "BEGIN ED25519 PRIVATE KEY" in env_key:
            return serialization.load_pem_private_key(env_key.encode("utf-8"), password=None)
        try:
            raw_bytes = bytes.fromhex(env_key)
            if len(raw_bytes) == 32:
                return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
        except Exception:
            pass

    # 3. Default repo keys path
    repo_root = Path(__file__).resolve().parent.parent
    default_key = repo_root / "keys" / "authority_ed25519_private.pem"
    if default_key.is_file():
        return serialization.load_pem_private_key(default_key.read_bytes(), password=None)

    raise ValueError("Authority Ed25519 private key not found in args, env, or keys/!")

def main():
    parser = argparse.ArgumentParser(description="Sign release verdict with Ed25519 authority key")
    parser.add_argument("--verdict", required=True, help="Path to release_verdict.json")
    parser.add_argument("--key", required=False, help="Path to authority_ed25519_private.pem")
    args = parser.parse_args()

    verdict_path = Path(args.verdict)
    if not verdict_path.is_file():
        print(f"ERROR: Verdict file not found: {verdict_path}", file=sys.stderr)
        sys.exit(1)

    try:
        privkey = load_private_key(args.key)
    except Exception as e:
        print(f"ERROR: Failed to load authority private key: {e}", file=sys.stderr)
        sys.exit(1)

    pubkey = privkey.public_key()
    raw_pub = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pubkey_fingerprint = hashlib.sha256(raw_pub).hexdigest()

    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: Failed to parse verdict JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Construct canonical signable payload binding the full lineage tuple
    signable_payload = {
        "authority": str(verdict.get("authority", "")).strip(),
        "authority_workflow": str(verdict.get("authority_workflow", "")).strip(),
        "authority_commit": str(verdict.get("authority_commit", "")).strip(),
        "authority_verifier_sha256": str(verdict.get("authority_verifier_sha256", "")).strip(),
        "authority_policy_sha256": str(verdict.get("authority_policy_sha256", "")).strip(),
        "authority_pubkey_fingerprint": pubkey_fingerprint,
        "evaluated_producer_repo": str(verdict.get("evaluated_producer_repo", "")).strip(),
        "evaluated_producer_commit": str(verdict.get("evaluated_producer_commit", "")).strip(),
        "evaluated_producer_run_id": str(verdict.get("evaluated_producer_run_id", "")).strip(),
        "evaluated_artifact_id": str(verdict.get("evaluated_artifact_id", "")).strip(),
        "evaluated_artifact_sha256": str(verdict.get("evaluated_artifact_sha256", "")).strip(),
        "verdict": str(verdict.get("verdict", "")).strip(),
        "status": str(verdict.get("status", "")).strip(),
        "adjudication_timestamp": str(verdict.get("adjudication_timestamp", "")).strip(),
    }

    canonical_bytes = json.dumps(signable_payload, sort_keys=True, indent=2).encode("utf-8")
    canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    signature_bytes = privkey.sign(canonical_bytes)
    signature_hex = signature_bytes.hex()

    verdict["authority_pubkey_fingerprint"] = pubkey_fingerprint
    verdict["canonical_payload_sha256"] = canonical_sha256
    verdict["ed25519_signature"] = {
        "algorithm": "Ed25519 (RFC 8032)",
        "public_key_fingerprint": pubkey_fingerprint,
        "signed_canonical_payload_sha256": canonical_sha256,
        "signature_hex": signature_hex
    }

    verdict_path.write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")

    print("================================================================================")
    print("✨ SOVEREIGN RELEASE VERDICT ASYMMETRICALLY SIGNED (RFC 8032)")
    print(f"   Authority:               {signable_payload['authority']}")
    print(f"   Producer Commit:         {signable_payload['evaluated_producer_commit']}")
    print(f"   Producer Run ID:         {signable_payload['evaluated_producer_run_id']}")
    print(f"   Artifact SHA-256:        {signable_payload['evaluated_artifact_sha256']}")
    print(f"   Public Key Fingerprint:  {pubkey_fingerprint}")
    print(f"   Canonical Payload SHA:   {canonical_sha256}")
    print(f"   Ed25519 Signature:       {signature_hex[:32]}... ({len(signature_bytes)} bytes)")
    print("================================================================================")

if __name__ == "__main__":
    main()
