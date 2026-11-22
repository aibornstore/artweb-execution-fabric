# Security Analysis Ingestion — P1

This is a **local-only analysis adapter**, not a scanner or runtime capability. It imports previously generated Nmap XML and OWASP ZAP *Traditional JSON* exports into `security.analysis/v1` and compares observations using `security.analysis-delta/v1`.

## Commands

```sh
go test ./pkg/securityanalysis ./cmd/analysis-ingest -count=1
go vet ./pkg/securityanalysis ./cmd/analysis-ingest
go run ./cmd/analysis-ingest nmap scan.xml report.json
go run ./cmd/analysis-ingest zap zap.json report.json
go run ./cmd/analysis-ingest diff previous.json current.json delta.json
```

Outputs have SHA-256 of their input export, deterministic finding IDs, sorted findings and bounded size. Existing report files are not overwritten. Userinfo, URL query and URL fragments are removed from ZAP targets. Request/response bodies, request headers and cookies are not copied into normalized reports. **URL paths and titles can still contain source-sensitive data** and must be treated accordingly.

Nmap `open|filtered` is **not** classified as a confirmed open service. The diff's `no_longer_observed` field is not evidence of remediation; meaningful comparisons require similar coverage and scope. Raw source hashes provide traceability but do **not** authenticate the external scanner or prove the export was complete.

## Architecture boundary

Existing `internal/cutover/evidence.go` accepts `artweb.bridge-authenticated-evidence/v1` from signed Bridge commands. This offline report **must never be passed to cutover.Evaluate**, be treated as authenticated command evidence, or authorize promotion.

For REAF / START integration, link normalized analysis findings by stable ID and `source_sha256` into a separately scoped **Analysis Evidence** graph. Bind to **Execution Evidence** only if a separate, validated Bridge command/result proves an execution. The current PR does **not** modify the BCP protocol, grants, relay, worker, runtime, or promotion policies. No active scans are triggered.

## Follow-on gates

1. Verify canonical REAF graph store + MAIN/HANDOFF, then add a typed offline ingestion sink and provenance edge schema.
2. Add offline TShark JSON/PCAP-derived records only after the schema and representative input data are checked.
3. Add scoped ZAP passive automation separately, without unintended active-scanner jobs.
4. Run Go 1.27 repository-wide regression, then a shadow deployment with rollback before runtime promotion.

Rollback: revert this PR / remove `pkg/securityanalysis`, `cmd/analysis-ingest` and this document.
