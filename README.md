# confidential-affine

Public Tinfoil **measured config** for Vendo's confidential Affine tier. Tinfoil
measures `tinfoil-config.yml` for remote attestation, so this repo is public by
design. App images are pinned by `@sha256` digest. See the design record in the
Vendo monorepo (`docs/superpowers/specs/2026-06-29-confidential-tier-affine-decisions.md`).

Status: **S1** — stock Affine + in-enclave Postgres + Redis, debug, no durability yet.
