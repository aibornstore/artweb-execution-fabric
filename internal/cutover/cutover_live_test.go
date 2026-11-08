package cutover

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mockDeviceLookup struct {
	devices map[string]DeviceEntry
	err     error
}

func (m *mockDeviceLookup) GetDevice(id string) (DeviceEntry, error) {
	if m.err != nil {
		return DeviceEntry{}, m.err
	}
	d, ok := m.devices[id]
	if !ok {
		return DeviceEntry{}, errors.New("device not found")
	}
	return d, nil
}

func ev(now time.Time, n int, boot, status string, k Key) []byte {
	e := Evidence{
		Schema: EvidenceSchema, GeneratedAt: now.Add(time.Duration(n) * time.Minute).Format(time.RFC3339Nano),
		MachineID: k.MachineID, Project: k.Project, Capability: k.Capability, Target: k.Target,
		Status: status, CommandID: fmt.Sprintf("cmd-%d", n),
		ResultSHA256: fmt.Sprintf("%064x", n+1), BootID: boot, AgentVersion: "bridge-test",
		EvidenceSource: "relay-authenticated-command",
	}
	b, _ := json.Marshal(e)
	return b
}

func TestPromotionLeaseRecoveryAndProfile(t *testing.T) {
	now := time.Now().UTC()
	k := Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/BridgeRead/test.txt"}
	var raws [][]byte
	for i := 0; i < 5; i++ {
		boot := "boot-a"
		if i >= 3 {
			boot = "boot-b"
		}
		raws = append(raws, ev(now.Add(-time.Hour), i, boot, "PASS", k))
	}
	p, err := Evaluate(raws, k, DefaultPolicy(), now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decision != DecisionBridgeEligible || p.RecommendedRoute != RouteBridgePrimary {
		t.Fatalf("promotion=%+v", p)
	}
	state := filepath.Join(t.TempDir(), "routes")
	pr, _ := json.Marshal(p)
	tr, err := Apply(state, pr, now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Route != RouteBridgePrimary {
		t.Fatalf("route=%s", tr.Route)
	}
	e, _, _, err := Resolve(state, k, now, nil)
	if err != nil || e.Route != RouteBridgePrimary {
		t.Fatalf("resolve=%+v err=%v", e, err)
	}

	fail := append(raws, ev(now, -1, "boot-b", "FAIL", k))
	p2, err := Evaluate(fail, k, DefaultPolicy(), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Decision != DecisionRecovery {
		t.Fatalf("expected recovery: %+v", p2)
	}
	pr2, _ := json.Marshal(p2)
	tr2, err := Apply(state, pr2, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if tr2.Route != RouteRecoveryFallback {
		t.Fatalf("route=%s", tr2.Route)
	}
}

func TestLegacyFallbackNormalizesAndMutationDenied(t *testing.T) {
	if IsReadOnlyCapability("service.restart@1") {
		t.Fatal("mutation capability must not be cutover-eligible")
	}
	if _, err := Evaluate(nil, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "service.restart@1", Target: "Spooler"}, DefaultPolicy(), time.Now()); err == nil {
		t.Fatal("mutation must fail closed")
	}
	if got := normalizeRoute(LegacyRDCFallback); got != RouteRecoveryFallback {
		t.Fatalf("legacy=%s", got)
	}
}

func TestPublisherDenyBlocksRouting(t *testing.T) {
	state := filepath.Join(t.TempDir(), "routes")
	if _, err := Apply(state, []byte(`{"schema":"artweb.bridge-capability-promotion/v2","generated_at":"`+time.Now().Add(-time.Hour).Format(time.RFC3339Nano)+`","key":{"machine_id":"HOME-2","project":"GLOBAL","capability":"fs.read@1","target":"D:/test"},"decision":"BRIDGE_PRIMARY_ELIGIBLE","lease_valid_until":"`+time.Now().Add(time.Hour).Format(time.RFC3339Nano)+`","evidence_corpus_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`), time.Now()); err != nil {
		t.Fatal(err)
	}

	lookup := &mockDeviceLookup{
		devices: map[string]DeviceEntry{
			"HOME-2": {ID: "HOME-2", Generation: "v2", Fingerprint: "fp-abc123", RoutingEligible: true, PublisherDeny: true},
		},
	}

	e, found, _, err := Resolve(state, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"}, time.Now(), lookup)
	if err == nil || found {
		t.Fatalf("expected resolve to fail when publisher-denied: entry=%+v found=%v err=%v", e, found, err)
	}
	if !strings.Contains(err.Error(), "publisher-denied") {
		t.Fatalf("expected 'publisher-denied' error, got: %v", err)
	}
}

func TestDeviceNotRoutingEligibleBlocks(t *testing.T) {
	state := filepath.Join(t.TempDir(), "routes")
	if _, err := Apply(state, []byte(`{"schema":"artweb.bridge-capability-promotion/v2","generated_at":"`+time.Now().Add(-time.Hour).Format(time.RFC3339Nano)+`","key":{"machine_id":"HOME-2","project":"GLOBAL","capability":"fs.read@1","target":"D:/test"},"decision":"BRIDGE_PRIMARY_ELIGIBLE","lease_valid_until":"`+time.Now().Add(time.Hour).Format(time.RFC3339Nano)+`","evidence_corpus_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`), time.Now()); err != nil {
		t.Fatal(err)
	}

	lookup := &mockDeviceLookup{
		devices: map[string]DeviceEntry{
			"HOME-2": {ID: "HOME-2", Generation: "v2", Fingerprint: "fp-abc123", RoutingEligible: false, PublisherDeny: false},
		},
	}

	e, found, _, err := Resolve(state, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"}, time.Now(), lookup)
	if err == nil || found {
		t.Fatalf("expected resolve to fail when not routing eligible: entry=%+v found=%v err=%v", e, found, err)
	}
	if !strings.Contains(err.Error(), "not routing eligible") {
		t.Fatalf("expected 'not routing eligible' error, got: %v", err)
	}
}

func TestExpiredLeaseRejectsInsteadOfRecovery(t *testing.T) {
	state := filepath.Join(t.TempDir(), "routes")
	// Apply with a future lease so state gets stored
	if _, err := Apply(state, []byte(`{"schema":"artweb.bridge-capability-promotion/v2","generated_at":"`+time.Now().Add(-time.Hour).Format(time.RFC3339Nano)+`","key":{"machine_id":"HOME-2","project":"GLOBAL","capability":"fs.read@1","target":"D:/test"},"decision":"BRIDGE_PRIMARY_ELIGIBLE","lease_valid_until":"`+time.Now().Add(time.Hour).Format(time.RFC3339Nano)+`","evidence_corpus_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`), time.Now()); err != nil {
		t.Fatal(err)
	}

	lookup := &mockDeviceLookup{}

	// Resolve after lease has expired
	future := time.Now().Add(2 * time.Hour)
	e, found, _, err := Resolve(state, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"}, future, lookup)
	if err == nil {
		t.Fatalf("expected resolve to reject expired lease: entry=%+v found=%v", e, found)
	}
	if !strings.Contains(err.Error(), "lease expired") {
		t.Fatalf("expected 'lease expired' error, got: %v", err)
	}
}

func TestProfileRequiresEveryCapabilityPrimary(t *testing.T) {
	state := filepath.Join(t.TempDir(), "profile")
	r, err := EvaluateProfile(state, "bridge-current-minimum-v1", "HOME-2", "GLOBAL", map[string]string{
		"host.status@1": "HOME-2", "fs.read@1": "D:/BridgeRead/test.txt",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.RDCIndependent {
		t.Fatal("empty routing state must not be independent")
	}
	if r.Decision != "RECOVERY_REQUIRED" {
		t.Fatalf("decision=%s", r.Decision)
	}
}

func TestMaintenanceRoutePrecedenceOverDeviceChecks(t *testing.T) {
	state := filepath.Join(t.TempDir(), "routes")
	now := time.Now().UTC()

	// First apply a BridgePrimary promotion
	p := PromotionReceipt{
		Schema:               PromotionSchema,
		GeneratedAt:          now.Add(-time.Hour).Format(time.RFC3339Nano),
		Key:                  Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"},
		Decision:             DecisionBridgeEligible,
		RecommendedRoute:     RouteBridgePrimary,
		EvidenceCount:        5,
		FreshPassCount:       5,
		DistinctFreshBoots:   2,
		EvidenceCorpusSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LeaseValidUntil:      now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	pr, _ := json.Marshal(p)
	if _, err := Apply(state, pr, now); err != nil {
		t.Fatal(err)
	}

	// Now apply Maintenance decision
	maint := PromotionReceipt{
		Schema:               PromotionSchema,
		GeneratedAt:          now.Format(time.RFC3339Nano),
		Key:                  Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"},
		Decision:             DecisionMaintenance,
		EvidenceCorpusSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	pm, _ := json.Marshal(maint)
	tr, err := Apply(state, pm, now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Route != RouteMaintenance {
		t.Fatalf("expected MAINTENANCE route, got %s", tr.Route)
	}

	// Resolve should return Maintenance even with publisher-denied device
	lookup := &mockDeviceLookup{
		devices: map[string]DeviceEntry{
			"HOME-2": {ID: "HOME-2", Generation: "v2", Fingerprint: "fp-abc123", RoutingEligible: true, PublisherDeny: true},
		},
	}

	e, found, _, err := Resolve(state, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"}, now, lookup)
	if err != nil || !found || e.Route != RouteMaintenance {
		t.Fatalf("expected Maintenance route to be returned despite publisher-denied: entry=%+v found=%v err=%v", e, found, err)
	}
}

func TestMaintenanceRoutePrecedenceOverExpiredLease(t *testing.T) {
	state := filepath.Join(t.TempDir(), "routes")
	now := time.Now().UTC()

	// Apply Maintenance directly (no BridgePrimary first)
	maint := PromotionReceipt{
		Schema:               PromotionSchema,
		GeneratedAt:          now.Format(time.RFC3339Nano),
		Key:                  Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"},
		Decision:             DecisionMaintenance,
		EvidenceCorpusSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	pm, _ := json.Marshal(maint)
	tr, err := Apply(state, pm, now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Route != RouteMaintenance {
		t.Fatalf("expected MAINTENANCE route, got %s", tr.Route)
	}

	// Advance time past what would be lease expiration
	future := now.Add(2 * time.Hour)

	// Resolve should still return Maintenance (no lease check)
	e, found, _, err := Resolve(state, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"}, future, nil)
	if err != nil || !found || e.Route != RouteMaintenance {
		t.Fatalf("expected Maintenance route despite time advancement: entry=%+v found=%v err=%v", e, found, err)
	}
}

func TestMaintenanceRouteNotRoutingEligibleStillWorks(t *testing.T) {
	state := filepath.Join(t.TempDir(), "routes")
	now := time.Now().UTC()

	maint := PromotionReceipt{
		Schema:               PromotionSchema,
		GeneratedAt:          now.Format(time.RFC3339Nano),
		Key:                  Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"},
		Decision:             DecisionMaintenance,
		EvidenceCorpusSHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	pm, _ := json.Marshal(maint)
	if _, err := Apply(state, pm, now); err != nil {
		t.Fatal(err)
	}

	lookup := &mockDeviceLookup{
		devices: map[string]DeviceEntry{
			"HOME-2": {ID: "HOME-2", Generation: "v2", Fingerprint: "fp-abc123", RoutingEligible: false, PublisherDeny: false},
		},
	}

	e, found, _, err := Resolve(state, Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/test"}, now, lookup)
	if err != nil || !found || e.Route != RouteMaintenance {
		t.Fatalf("expected Maintenance route despite not routing eligible: entry=%+v found=%v err=%v", e, found, err)
	}
}

func TestProfileAcceptsMaintenanceAsPrimary(t *testing.T) {
	state := filepath.Join(t.TempDir(), "profile")
	now := time.Now().UTC()

	// Profile evaluation should accept Maintenance as valid (like BridgePrimary)
	// Both capabilities used by the profile must be in Maintenance,
	// applied with matching targets so Resolve finds the entries.
	maintHost := PromotionReceipt{
		Schema:               PromotionSchema,
		GeneratedAt:          now.Format(time.RFC3339Nano),
		Key:                  Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "host.status@1", Target: "HOME-2"},
		Decision:             DecisionMaintenance,
		EvidenceCorpusSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	pm, _ := json.Marshal(maintHost)
	if _, err := Apply(state, pm, now); err != nil {
		t.Fatal(err)
	}

	maintFs := PromotionReceipt{
		Schema:               PromotionSchema,
		GeneratedAt:          now.Format(time.RFC3339Nano),
		Key:                  Key{MachineID: "HOME-2", Project: "GLOBAL", Capability: "fs.read@1", Target: "D:/BridgeRead/test.txt"},
		Decision:             DecisionMaintenance,
		EvidenceCorpusSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	pm, _ = json.Marshal(maintFs)
	if _, err := Apply(state, pm, now); err != nil {
		t.Fatal(err)
	}

	r, err := EvaluateProfile(state, "bridge-current-minimum-v1", "HOME-2", "GLOBAL", map[string]string{
		"host.status@1": "HOME-2", "fs.read@1": "D:/BridgeRead/test.txt",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.BridgePrimary {
		t.Fatal("Maintenance route should satisfy BridgePrimary in profile")
	}
	if r.Decision != "BRIDGE_PRIMARY" {
		t.Fatalf("expected BRIDGE_PRIMARY decision, got %s", r.Decision)
	}
}
