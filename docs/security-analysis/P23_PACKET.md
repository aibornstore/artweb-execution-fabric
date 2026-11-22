# P2.3 — immutable shadow transfer packet

**Scope:** Export and validate a deterministic offline package for the existing START/REAF staging contract without creating a second graph database or executing scanners.

## CLI

```sh
go run ./cmd/analysis-ingest tshark packets.json normalized.json
go run ./cmd/analysis-ingest seal normalized.json artweb-security artweb.security p23-shadow.zip
go run ./cmd/analysis-ingest verify-packet p23-shadow.zip p23-readback.json
```

`seal` writes only if the destination is absent, fsyncs, then reopens and validates the ZIP. `verify-packet` likewise writes its readback receipt exclusively. Both operate on local files.

Packet members (fixed names, fixed ordering, stored rather than compressed, fixed ZIP timestamps):
- `report.json`: the normalized, unverified scanner export observations;
- `graph.json`: candidate U8PI P1–P8 projection, relations have no dangling endpoints;
- `start-envelope.json`: exact candidate for the pre-existing START/REAF `START_REAF_INPUT_V0.1` validator, with `authority.execute_external=false`;
- `manifest.json`: source report SHA-256, project, namespace, member sizes and member SHA-256 hashes, trust status `UNATTESTED_INPUT_SHADOW_ONLY`.

`verify-packet` checks the ZIP member allowlist/size/type, parses the normalized report, independently regenerates the graph, envelope and manifest, then rejects any ZIP not byte-identical to a canonical rebuild. The receipt is `security.analysis-shadow-readback/v1` with `INPUT_VALIDATED_SHADOW_ONLY`. This establishes **local internal consistency**, not authenticity of a scan performed elsewhere, and not independent REAF MAIN acceptance. A person who controls all input bytes can construct a self-consistent packet; no cryptographic signature or remote attestation is claimed.

The historical library canonical input contract is `/ArtWeb/START/HANDOFFS/START_REAF_INTEGRATION_001_20261019.zip`; its `TOOLS/reaf_prepare.py` validates extracted `start-envelope.json`. The existing HOME-2 `D:\_research\ATOM_RECOMB\REAF_INGRESS_POLICY.md` is domain-specific research-only, not an authorized write endpoint for security observations. The S18 SQLite/WAL shadow mechanism is scoped to a different bridge test and should not be reused as a substitute for global REAF.

## Gates

1. Local `go test ./pkg/securityanalysis ./cmd/analysis-ingest -count=1` and `go vet`, including deterministic repeat and corrupted/forged ZIP rejection.
2. Extract `start-envelope.json`, validate with the original `reaf_prepare.py`; require `INPUT_VALIDATED_ONLY`, 8 types, `execute_external=false`.
3. Run targeted Go 1.27.3 tests on a separately downloaded GitHub PR source snapshot.
4. Before release, complete full repository Go 1.27 regression and discover a **verified** main graph ingestion interface with readback; **do not** write a production or scientific graph during P2.3.

Rollback: revert this Draft PR. No new global runtime, scheduler, database or recurring monitor is created.
