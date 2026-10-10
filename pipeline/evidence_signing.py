#!/usr/bin/env python3
"""Sign and verify gate evidence.

The evidence artefact was already *bound* to its plan -- it carries the plan's
SHA-256 -- so a verdict could not be quietly moved onto a different plan. But
the artefact itself was a plain JSON file: anyone could edit a violation out of
it afterwards and nothing would show. This module closes that gap with an
Ed25519 signature an assessor can check using only a published public key.

**What is signed.** A canonical serialisation of the whole evidence document,
minus the signature block itself: keys sorted, no insignificant whitespace,
UTF-8. Re-indenting the file does not invalidate it; changing any value does.

**What a valid signature proves.** That the evidence was produced by a holder of
the signing key and has not changed since. How much that is worth depends on
who holds the key, which is why the signing key lives only in CI (a GitHub
Actions secret) and not on a developer's machine: a developer who could re-sign
edited evidence would defeat the point. See ../README.md.

**What it does not prove.** When. The `signed_at` field is asserted by the
signer, not attested by a third party; an RFC 3161 timestamp or a transparency
log would be needed for that, and both are out of scope here.

Usage:
    python evidence_signing.py keygen --private key.pem --public public.pem
    python evidence_signing.py sign   --evidence e.json [--key key.pem]   # or $CSCF_EVIDENCE_SIGNING_KEY
    python evidence_signing.py verify --evidence e.json [--public-key public.pem]
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALGORITHM = "Ed25519"
CANONICALISATION = "json: sorted keys, compact separators, UTF-8, signature block removed"
KEY_ENV = "CSCF_EVIDENCE_SIGNING_KEY"
DEFAULT_PUBLIC_KEY = Path(__file__).resolve().parents[1] / "keys" / "evidence_signing_public.pem"


def canonical_bytes(evidence: dict) -> bytes:
    body = {k: v for k, v in evidence.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def key_id(public_key: Ed25519PublicKey) -> str:
    """A short, stable fingerprint of the public key."""
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def load_private_key(pem: bytes | str) -> Ed25519PrivateKey:
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key is not an Ed25519 private key")
    return key


def load_public_key(pem: bytes | str) -> Ed25519PublicKey:
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("verification key is not an Ed25519 public key")
    return key


def sign(evidence: dict, private_key: Ed25519PrivateKey) -> dict:
    """Return a copy of the evidence with a signature block attached."""
    message = canonical_bytes(evidence)
    signed = {k: v for k, v in evidence.items() if k != "signature"}
    signed["signature"] = {
        "algorithm": ALGORITHM,
        "key_id": key_id(private_key.public_key()),
        "canonicalisation": CANONICALISATION,
        "digest_sha256": hashlib.sha256(message).hexdigest(),
        "signed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "value": base64.b64encode(private_key.sign(message)).decode("ascii"),
    }
    return signed


def verify(evidence: dict, public_key: Ed25519PublicKey) -> tuple[str, str]:
    """('valid' | 'invalid' | 'unsigned', human-readable reason)."""
    block = evidence.get("signature")
    if not block:
        return "unsigned", "the evidence carries no signature"
    if block.get("algorithm") != ALGORITHM:
        return "invalid", f"unsupported signature algorithm {block.get('algorithm')!r}"
    if block.get("key_id") != key_id(public_key):
        return "invalid", (
            f"signed with key {block.get('key_id')}, not the published key {key_id(public_key)}"
        )

    message = canonical_bytes(evidence)
    try:
        public_key.verify(base64.b64decode(block["value"]), message)
    except (InvalidSignature, ValueError, KeyError):
        return "invalid", "the signature does not match -- the evidence has been altered"
    if block.get("digest_sha256") != hashlib.sha256(message).hexdigest():
        return "invalid", "the recorded digest does not match the evidence"
    return "valid", f"{ALGORITHM} signature by key {block['key_id']}, signed {block.get('signed_at', '?')}"


def private_key_from(path: str | None) -> Ed25519PrivateKey | None:
    """The signing key from a file, or from the environment (CI)."""
    if path:
        return load_private_key(Path(path).read_bytes())
    pem = os.environ.get(KEY_ENV)
    return load_private_key(pem) if pem else None


# ============================================================================
# CLI
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Sign and verify CSCF gate evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 key pair")
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)

    signp = sub.add_parser("sign", help="sign an evidence file in place")
    signp.add_argument("--evidence", type=Path, required=True)
    signp.add_argument("--key", help=f"private key file (default: ${KEY_ENV})")

    verifyp = sub.add_parser("verify", help="verify an evidence file")
    verifyp.add_argument("--evidence", type=Path, required=True)
    verifyp.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    verifyp.add_argument(
        "--require", action="store_true", help="treat an unsigned file as a failure"
    )

    args = parser.parse_args()

    if args.command == "keygen":
        key = Ed25519PrivateKey.generate()
        args.private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        args.public.parent.mkdir(parents=True, exist_ok=True)
        args.public.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        print(f"key pair written; key id {key_id(key.public_key())}")
        return 0

    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))

    if args.command == "sign":
        key = private_key_from(args.key)
        if key is None:
            print(f"ERROR: no signing key (pass --key or set ${KEY_ENV})", file=sys.stderr)
            return 2
        args.evidence.write_text(json.dumps(sign(evidence, key), indent=2), encoding="utf-8")
        print(f"signed {args.evidence} with key {key_id(key.public_key())}")
        return 0

    status, reason = verify(evidence, load_public_key(args.public_key.read_bytes()))
    print(f"{status.upper()}: {args.evidence.name} -- {reason}")
    if status == "valid":
        return 0
    if status == "unsigned" and not args.require:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
