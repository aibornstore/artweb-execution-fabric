# Security Analysis P2 — source-bounded, candidate U8PI projection

## Current binding

The existing Go module is `github.com/aibornstore/artweb-execution-fabric`.
Its `internal/cutover/evidence.go` expects signed relay-command evidence
(`artweb.bridge-authenticated-evidence/v1`). It does not provide an authorized
REAF graph write API. Thus `analysis-ingest graph` emits a deterministic,
**unattested candidate**; it does not register anything in the runtime graph.

The read-only HOME-2 inspection of `D:\PROJECTS\artweb-execution-fabric` and
`D:\PROJECTS\_INBOX\REAF_CODE_MODE_R2_SHADOW_20261120\source` confirmed
Bridge-oriented source trees but not an evidence-graph sink. The existing U8PI
profile requires P1 Entity, P2 State, P3 Action, P4 Relation, P5 Resource,
P6 Constraint, P7 Goal and P8 Result/Evidence, with no new ninth primitive.

## Offline inputs and commands

From the module root:

```sh
go test ./pkg/securityanalysis ./cmd/analysis-ingest -count=1
go vet ./pkg/securityanalysis ./cmd/analysis-ingest
go run ./cmd/analysis-ingest tshark captures/packets.json results/packets.normalized.json
go run ./cmd/analysis-ingest graph results/packets.normalized.json results/packets.u8pi.json
```

To generate a TShark source export **from an existing PCAP** in a separate
operator-controlled environment (not performed by this package):

```sh
tshark -r example.pcap -T json -J 'frame ip ipv6 tcp udp' > packets.json
```

`-T json` is the documented TShark JSON format. Import only selected network
endpoint facts, **not** raw payloads, DNS names, HTTP requests, TLS SNI,
headers or source addresses/ports. A traffic destination does not prove a
listening service, let alone a vulnerability. No code here starts TShark.

The `docs/security-analysis/zap-passive-har.yaml` template processes recorded HAR
responses using ZAP Automation Framework's `import` (`type: har`,
`sendRequests: false`), `passiveScan-config`, `passiveScan-wait` and `report`
with `traditional-json`, without spidering, request replay or active scanning.
Adjust `env.contexts[].urls` and `fileName` to the authorized captured site.
The example domain and HAR name are placeholders. ZAP is not executed here and
its configuration is not yet validated with `-autocheck` on a real ZAP binary.

Reference docs:
- https://www.wireshark.org/docs/man-pages/tshark
- https://www.zaproxy.org/docs/desktop/addons/import-export/automation/
- https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-pscanconf/
- https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-pscanwait/
- https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/

## Graph payload semantics

`security.analysis-u8pi-projection/v1` includes:
- P1 target Entity nodes;
- P2 provenance State, explicitly unverified;
- P3 local projection Action (not external scan execution);
- P4 typed Relations, checked for dangling links;
- P5 hashed input Resource;
- P6 prohibition on bridge-promotion Constraint;
- P7 observation Goal;
- P8 report and per-snapshot observation Result/Evidence.

Only a validated link to *separate* signed Bridge command evidence may establish
scanner-execution provenance. A source checksum alone is not proof of external
origin. Graph nodes are stable across reprocessing; report occurrence nodes are
scoped to a source checksum so earlier observations are not overwritten. This
is an exchange format for a future confirmed sink, not a parallel database.

Next gate: locate the authoritative REAF graph sink plus its schema and
allowed write method; validate input mapping, then enable a SHADOW-only sink
with explicit rollback. No writes or runtime promotion were performed here.

## START/REAF staging adapter — P2.1

A canonical staging input contract was found in Library archive
`/ArtWeb/START/HANDOFFS/START_REAF_INTEGRATION_001_20261019.zip`.
Its original `TOOLS/reaf_prepare.py` requires `project_id`, `namespace`,
`purpose`, nonempty unique `sources`, `authority.execute_external`,
and a provenance-linked `primitives` array containing P1–P8.

`analysis-ingest stage <report.json> <project-id> <namespace> <envelope.json>`
creates `START_REAF_INPUT_V0.1`-compatible JSON, retaining source SHA-256
and deterministic, namespace-scoped primitive records. The command always sets
`execute_external: false`. No REAF binary is loaded.

Validation on the standalone equivalent P2.1 source using the **original**
`reaf_prepare.py`: `INPUT_VALIDATED_ONLY`, eight primitive types, 21 atoms
from the TShark demo, `reaf_engine_executed: false`. A deliberately foreign
namespace was rejected; original Python contract tests passed 3/3.
Go 1.23.2 targeted unit tests and vet passed locally. Full Go 1.27
repository suite, current REAF runtime, actual graph persistence: **NOT RUN**.

The REAF 118 synergy ITER021 package is an unrelated candidate training lane,
not evidence of an authoritative security-analysis graph write API. It was
inspected read-only, not modified or merged.
