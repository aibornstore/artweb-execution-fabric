package securityanalysis

import (
	"encoding/json"
	"strings"
	"testing"
)

func startTestEnvelope(t *testing.T) STARTEnvelope {
	t.Helper()
	report, err := Parse("nmap", []byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`))
	if err != nil { t.Fatal(err) }
	out, err := ProjectSTART(report, "test-project", "artweb.security")
	if err != nil { t.Fatal(err) }
	return out
}
func cloneStart(t *testing.T, in STARTEnvelope) STARTEnvelope {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil { t.Fatal(err) }
	var out STARTEnvelope
	if err := json.Unmarshal(b, &out); err != nil { t.Fatal(err) }
	return out
}
func TestSTARTShadowGuardValidAfterJSONRoundTrip(t *testing.T) {
	env := cloneStart(t, startTestEnvelope(t))
	if err := ValidateSTARTShadow(env); err != nil { t.Fatal(err) }
}
func TestSTARTShadowRejectsDanglingCrossNamespaceAndUntrustedExecution(t *testing.T) {
	base := startTestEnvelope(t)
	variants := []struct {
		name string
		mutate func(*STARTEnvelope)
	}{
		{"dangling", func(e *STARTEnvelope) {
			for i := range e.Primitives {
				if e.Primitives[i].Type == "P4" {
					v := e.Primitives[i].Value.(map[string]any)
					v["to"] = "urn:security-analysis:missing"
					return
				}
			}
		}},
		{"cross_namespace", func(e *STARTEnvelope) { e.Primitives[0].Namespace = "another.tenant" }},
		{"unknown_source", func(e *STARTEnvelope) { e.Primitives[0].Provenance.Source = "sha256:" + strings.Repeat("0", 64) }},
		{"external_execution", func(e *STARTEnvelope) { e.Authority.ExecuteExternal = true }},
		{"duplicate_id", func(e *STARTEnvelope) { e.Primitives[1].ID = e.Primitives[0].ID }},
		{"missing_p8", func(e *STARTEnvelope) {
			for i := range e.Primitives { if e.Primitives[i].Type == "P8" { e.Primitives[i].Type = "P6" } }
		}},
		{"missing_source", func(e *STARTEnvelope) { e.Sources = nil }},
		{"invalid_source_hash", func(e *STARTEnvelope) { e.Sources[0] = "sha256:" + strings.Repeat("X", 64) }},
		{"invalid_relation", func(e *STARTEnvelope) {
			for i := range e.Primitives {
				if e.Primitives[i].Type == "P4" {
					e.Primitives[i].Value = map[string]any{"from": 5, "to": "x", "predicate": "rel"}
					return
				}
			}
		}},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneStart(t, base)
			tc.mutate(&candidate)
			if err := ValidateSTARTShadow(candidate); err == nil { t.Fatal("unexpected PASS") }
		})
	}
}
