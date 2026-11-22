# P2.6 — namespace-scoped U8PI staging (candidate only)

## Defect and decision

Legacy START v0.1 accepted namespaced atoms but `ProjectSTART` computed atom IDs and P4 endpoints from the global report/target alone. Identical findings in separate projects could therefore share IDs if an external graph store used `atom.id` as a global key. We **do not** change the legacy path: published P2.3/P2.5 packets must remain byte-for-byte identical.

P2.6 introduces an **opt-in** typed projection with every `id`, `canonical_id` and every P4 `from/to` bound to `(project_id, namespace, old atom ID)`. This avoids cross-project key collisions without changing the P1–P8 ontology or the existing START `START_REAF_INPUT_V0.1` syntax.

The new format is still **candidate staging**. `namespace` alone is not authentication or access control. A real receiver must separately authenticate tenant ownership and reject unauthorized tenant claims. Source hashes and visible finding values are still the original supplied data, not confidential tenant IDs.

## Commands

```sh
go run ./cmd/analysis-ingest nmap examples/nmap-demo.xml examples/scoped/report.json
go run ./cmd/analysis-ingest stage-scoped examples/scoped/report.json security-demo-a artweb.security examples/scoped/stage-a.json
go run ./cmd/analysis-ingest validate-stage-scoped-bound examples/scoped/report.json examples/scoped/stage-a.json examples/scoped/readback-a.json
```

`stage-scoped` is deterministic. `validate-stage-scoped-bound` is strict: input must match the report-derived v2 projection, unsalted v1 cannot masquerade as v2, unknown JSON fields/trailing objects are rejected, and no output is created on failure. Receipt status is `REPORT_NAMESPACE_SCOPED_STRUCTURAL_ONLY`, not REAF MAIN ACK.

### Reuse

- `ProjectSTART` + `ProjectU8PI`: unchanged; scoped v2 reuses their content and remaps identities.
- `ValidateSTARTShadow`: unchanged P1–P8, provenance, and dangling-edge guard, reused for v2.
- `readNormalizedReport`, `readBoundedRegular`, `writeExclusive`: existing CLI primitives reused.
- `SealPacket`, `VerifyPacket`, `VerifyPacketSource`: unchanged legacy packet V1.
- Original `START_REAF_INTEGRATION_001_20261019.zip/TOOLS/reaf_prepare.py`: reused unmodified for contract verification.

### Verification

- Go 1.23.2 `go test ./... -count=1`: PASS (two packages).
- Go 1.23.2 `go vet ./...`: PASS.
- Original `reaf_prepare.py` accepted both v2 envelopes: 8 primitive types / 16 atoms per test sample, `INPUT_VALIDATED_ONLY`, `reaf_engine_executed=false`.
- Original Python validator unit tests: 3/3 PASS.
- Different `project_id` with identical source+namespace: zero shared IDs across 16 atoms.
- Identical inputs/scope: byte-identical v2 envelope.
- Mixed foreign P4 endpoints, forged `canonical_id`, legacy v1 downgrade, no-overwrite receipt: REJECTED.
- Existing legacy packet P2.3 SHA-256: `6ea739641aa649bdef8edc4c6e7e4bd32086cb707d0857e0c9cdfd2ab419fcda` unchanged byte-for-byte.

### Release boundary / HOLD

HOME-2 has only ~199–204 MiB free RAM in fresh probes; SEO lacks Go on PATH; container Go is 1.23.2. No full parent Go 1.27.3 regression. No global REAF MAIN write endpoint or independent ACK confirmed. The REAF_118 synergy lane and ATOM_RECOMB are research-only. No production, existing bridge protocol or canonical REAF DB changed.

**Rollback:** revert the P2.6 commit; keep P2.5 artifacts intact. Do not replace old packets with v2 until the true REAF receiving contract and tenant ownership policy are verified.
