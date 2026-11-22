# P2.4 — START/REAF graph admission guard (SHADOW ONLY)

The original `START_REAF_INTEGRATION_001_20261019.zip/TOOLS/reaf_prepare.py` validates P1–P8 types, namespace and source references, but does **not** check P4 relation endpoints.

## Reproduced issue and fix

A candidate envelope with one P4 `value.to` replaced by `urn:security-analysis:not-present` received `INPUT_VALIDATED_ONLY` from the original START validator. The new Go `ValidateSTARTShadow` rejected it with `dangling relation`, and the CLI created **no receipt**.

- `pkg/securityanalysis/start_guard.go`: checks exactly one SHA-256 source, P1–P8, unique IDs, all per-atom namespace and source references, P4 fields and existence of both endpoints, and `execute_external=false`.
- `cmd/analysis-ingest/stage_guard.go`: `validate-stage <start-envelope.json> <guard-receipt.json>`, bounded local-file input and exclusive write; independent readback status `STRUCTURAL_VALIDATION_ONLY`.
- `ProjectSTART` calls this guard before emitting the existing START v0.1 envelope.

## Evidence (2026-11-22)

- Go 1.23.2 isolated: `go test ./pkg/securityanalysis ./cmd/analysis-ingest -count=1` PASS; `go vet` PASS.
- Original Python START tests: 3/3 PASS.
- Old P2.3 shadow packet re-sealed to **identical bytes**, SHA-256 `6ea739641aa649bdef8edc4c6e7e4bd32086cb707d0857e0c9cdfd2ab419fcda`.
- Known-good envelope: 21 U8PI atoms, 11 P4 edges, no external execution; `STRUCTURAL_VALIDATION_ONLY`.
- Malformed P4 negative: original Python accepted; Go guard rejected.
- Go 1.27.3 P2.4 checks NOT RUN; HOME-2 only 199400 KiB (~195 MiB) free at readback. No new compiler load.
- No real REAF MAIN graph ingestion endpoint or independent receiver ACK verified. **This is not production integration.**

## Preserved contracts

No mutation of original START validator, Bridge/grants/relay/cutover, canonical MAIN or production. Existing P2.3 binary packet and IDs remain unchanged. IDs in START v0.1 are content-stable, **not globally namespace-derived**; the actual REAF sink must enforce tenancy itself.

Rollback: revert Draft PR #1. Next gate: resource-adequate Go 1.27 full regression and verified canonical REAF sink with readback.