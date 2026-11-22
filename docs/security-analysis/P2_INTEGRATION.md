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
