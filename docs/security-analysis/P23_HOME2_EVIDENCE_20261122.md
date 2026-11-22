# P2.3 HOME-2 Go 1.27.3 readback — 2026-11-22

## TARGETED TESTS — PASS

Source: independently downloaded **GitHub PR #1 P2.3 branch snapshot** under:

`D:\PROJECTS\_INBOX\SECURITY_ANALYSIS_P23_20261122\artweb-execution-fabric-feature-security-analysis-p1-20261122`

Command initiated:

```cmd
go test ./pkg/securityanalysis ./cmd/analysis-ingest -count=1 && go vet ./pkg/securityanalysis ./cmd/analysis-ingest
```

Observed Go 1.27.3 Windows test results, before terminating the session:

```
ok  github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis  0.047s
ok  github.com/aibornstore/artweb-execution-fabric/cmd/analysis-ingest       1.320s
```

**Verdict:** Go 1.27.3 targeted unit tests **PASS** for both packages. The session's exit code was **1 due to manual termination during the subsequent vet step**, not a demonstrated unit-test failure. Go 1.27.3 `go vet` is **INCOMPLETE**. Local Go 1.23.2 `go vet` was PASS.

## RESOURCE SAFETY

A read-only HOME-2 Win32_OperatingSystem check showed:
- `FreePhysicalMemory=257924` KiB (~252 MiB);
- `TotalVisibleMemorySize=6212296` KiB (~5.93 GiB).

The targeted session PID 2600 was stopped due insufficient available RAM. Readback afterwards confirmed no `go.exe`, `compile.exe` or `vet.exe` in the test-process filter. No production service was stopped.

## FULL SUITE — INCOMPLETE

An earlier independent, isolated P2.2 `go test ./... -count=1` process PID 12728 ran longer than the bounded test window and was manually terminated. Successful package lines had already been emitted for:

- cmd/analysis-ingest
- cmd/bridge-relay
- cmd/bridgectl
- cmd/bridgecutover
- internal/auth
- internal/cutover
- internal/identity
- internal/limitedexec

The full suite's exit code **1 reflects termination**, not a complete failing test report. It must not be reported as repository-wide PASS or FAIL.

## NEXT GATE

Re-run **only** missing full-repository regression and Go 1.27.3 vet when memory/resource headroom is sufficient, or on an isolated runner. No canonical REAF graph store was accessed. The PR remains Draft and unmerged.
