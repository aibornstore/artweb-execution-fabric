# P2.8 — Windows CLI smoke and REAF MAIN receiver gate

**Date:** 2026-11-22  
**Source commit:** `3b8422bcc7af9b5106e36181802e231b4806ce1e` (Go code unchanged)  
**Execution:** `LOCAL_ONLY / PASS` on SEO Windows/amd64  
**Global REAF MAIN:** `UNKNOWN_NOT_RUN`

## Verified binary

- Portable Go 1.27.3 compiler: `E:\_research\START_SECURITY_ANALYSIS_P27_20261122\go\bin\go.exe`.
- Build: `go build -p 1 -trimpath -buildvcs=false -o dist/analysis-ingest.exe ./cmd/analysis-ingest`; process exit **0**.
- Windows executable: `E:\_research\START_SECURITY_ANALYSIS_P27_20261122\dist\analysis-ingest.exe`.
- Binary size: **5,654,016 bytes**.
- Binary SHA-256 read back using certutil: `33af1f2fcda35572ec10d80e260af6bb20c915e720d04f2066fff32fa062ae6e`.
- No PATH edit, service installation, browser, or network scan.
- Before this smoke, **full** `go test -p 1 -count=1 ./...` and `go vet -p 1 ./...` on this exact source commit had independently exited 0 with Go 1.27.3; see `P27_GO127_REGRESSION_20261122.md`.

## Offline integration smoke

Source: intentionally synthetic Nmap XML for documentation-only address `192.0.2.15:443/tcp`, nginx version 1.24. Second XML uses version 1.25. No network IO or Nmap binary executed.

From `E:\_research\START_SECURITY_ANALYSIS_P27_20261122\smoke_security_analysis_p28.py`, the actual native `analysis-ingest.exe` executed 10 CLI invocations:

| Command | Expected | Observed |
|---|---|---|
| `nmap` source 1 | import | PASS, exit 0 |
| `nmap` source 2 | import | PASS, exit 0 |
| `diff` | changed=1, added=0 | PASS, exit 0 |
| `stage-scoped` | project-scoped P1-P8 | PASS, exit 0 |
| `validate-stage-scoped-bound` | scoped readback | PASS, exit 0 |
| `seal` | legacy packet | PASS, exit 0 |
| `verify-packet` | deterministic integrity | PASS, exit 0 |
| `verify-source` (original) | replay matches | PASS, exit 0 |
| `verify-source` (modified) | reject | REJECTED, exit 1; no receipt |
| `seal` (same destination) | reject overwrite | REJECTED, exit 1 |

Observed readbacks:
- `REPORT_NAMESPACE_SCOPED_STRUCTURAL_ONLY`, 16 atoms / 8 relations.
- `SOURCE_BYTES_REPLAYED_LOCAL_ONLY`.
- `INPUT_VALIDATED_SHADOW_ONLY`.
- `external_execution=false`.
- Original source SHA-256: `dc2e2a91579ad1a1e36d6a837ec0eb4ddc6a55ac104df1295cea9f7b0688feb7`.
- Sealed packet SHA-256: `6d71c361373c6bdb223b61a7dcbb4abb99d07f758132bd7b7f4dd81ed5d4a174`.

Machine evidence: `E:\_research\START_SECURITY_ANALYSIS_P27_20261122\smoke_P28_20261122\SMOKE_EVIDENCE.json`, status `PASS`. Actual script exited 0.

## REAF MAIN reconciliation

Inspected current reachable devices: **SRVVLG offline**. The latest directly available `REAF_118_SYNERGY_ITER021` handoff explicitly marks the global REAF registry and accepted MAIN pair count **UNKNOWN**, and `MAIN_LOCAL_ITER021.md` explicitly states it is **not canonical MAIN**. The HOME-2 `ATOM_RECOMB` ingress and S18 local ledger are separately scoped research/shadow components, not authenticated global REAF receivers.

**There is no verified MAIN-owned receiver contract, tenant-authorization mechanism, input commit receipt or independently readable `recipient_main_ack` for this integration.** No global ingestion was attempted and no ACK was fabricated. The requested production REAF graph write remains `HOLD`. The current offline CLI can accept already existing user-provided scanner exports without opening network ports.

## Next gate

1. Reconcile the actual REAF MAIN owner, immutable source/schema and permitted inbound location when its host becomes available.
2. Check receiver identity, tenant authorization, namespace ownership, accepted schema, immutable source digest and allowed append-only mutation boundaries.
3. Send one bounded candidate from an authorized actor; require **receiver-generated** ACK with exact submitted content digest, receipt ID and independent post-commit graph readback.
4. Compare the receipt with the preimage, record rollback and only then consider promotion/merge.

No new database, automation, task scheduler, global config or production mutation. This PR remains **DRAFT / NOT MERGED**.
