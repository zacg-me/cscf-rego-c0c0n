# Evidence-signing key

`evidence_signing_public.pem` is the Ed25519 public key CI signs gate evidence
with. The private key exists only as the `CSCF_EVIDENCE_SIGNING_KEY` Actions
secret of this repository; no copy is kept. Verify evidence with

    python pipeline/evidence_signing.py verify --require --evidence <file>

To rotate: generate a new pair with `pipeline/evidence_signing.py keygen`, set
the secret, commit the new public key, and re-run CI to re-sign the reference
artefacts.
