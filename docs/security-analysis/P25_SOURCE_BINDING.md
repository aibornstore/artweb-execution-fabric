# P2.5 — bound-source and exact-report verification (SHADOW)

No additional database, scheduler, remote scanner, or production route is created.

## Why

P2.4 `verify-packet` checks internal ZIP consistency, but a self-consistent packet could contain scanner observations from arbitrary original bytes. The existing `validate-stage` checks graph shape but permits invented values on existing P1/P8 nodes. Neither is an authenticated REAF MAIN acknowledgement.

## Commands

```sh
go run ./cmd/analysis-ingest verify-source tshark original.json packet.zip source-receipt.json
go run ./cmd/analysis-ingest validate-stage-bound report.json start-envelope.json bound-receipt.json
```

`verify-source` checks the sealed packet, reparses the original export with the same Nmap/ZAP/TShark importer, compares the source SHA-256 and the **exact canonical normalized findings bytes** with the packet. Its receipt is `security.analysis-source-replay/v1` with status `SOURCE_BYTES_REPLAYED_LOCAL_ONLY`. This proves local reproducibility from the supplied bytes, **not** that a trusted tool actually produced those bytes.

`validate-stage-bound` compares the entire incoming START envelope with the deterministic projection derived from the supplied normalized report, in addition to the existing topology/source/namespace guard. Unrecognized fields, trailing objects, fabricated observations or a different report are rejected before any receipt can be written. Its status is `REPORT_BOUND_STRUCTURAL_ONLY`.

These commands add no new permissions and do not run an external scanner. Their output files use exclusive-write semantics, so a duplicate receipt cannot silently overwrite prior evidence.

## Verification

- Local Go 1.23.2 targeted package tests and `go vet`: PASS.
- Original P2.3 sealed packet SHA-256 `6ea739641aa649bdef8edc4c6e7e4bd32086cb707d0857e0c9cdfd2ab419fcda` read back under P2.5 without modification.
- TShark source replay example: two observations, source hash `664862074dfcd8d70d7e250ff7e88baeb713991afd89c2cd994258ae6eee00e6`.
- START envelope bound to its original normalized report: 21 primitives and 11 relations, external execution disabled.
- Negative tests: modified source, wrong tool, malformed packet, fabricated but topologically-valid START observation, different report, and receipt overwrite: rejected.
- The original START validator and canonical scientific/production REAF stores are unchanged.
- Go 1.27.3 whole-repository regression: HOLD (HOME-2 was low on RAM; no runtime tests launched there during this iteration).
- Verified global REAF MAIN sink and independent receiver ACK: UNKNOWN / HOLD.

Rollback: revert the unmerged Draft PR. P2.4 packet remains byte-for-byte compatible.
