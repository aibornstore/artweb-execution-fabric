package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func TestScopedStageCLIValidationAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.xml")
	report := filepath.Join(dir, "normalized.json")
	stage := filepath.Join(dir, "scoped.json")
	receipt := filepath.Join(dir, "scoped-receipt.json")
	input := []byte(`<nmaprun><host><address addr="192.0.2.42" addrtype="ipv4"/><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`)
	if err := os.WriteFile(source, input, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("nmap", source, report); err != nil {
		t.Fatal(err)
	}
	if err := runStageScoped(report, "project-a", "project.security", stage); err != nil {
		t.Fatal(err)
	}
	if err := runValidateStageScopedBound(report, stage, receipt); err != nil {
		t.Fatal(err)
	}
	if err := runValidateStageScopedBound(report, stage, receipt); err == nil {
		t.Fatal("receipt overwritten")
	}
	data, err := os.ReadFile(stage)
	if err != nil {
		t.Fatal(err)
	}
	var envelope securityanalysis.STARTEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	for i := range envelope.Primitives {
		if envelope.Primitives[i].Type == "P1" {
			envelope.Primitives[i].CanonicalID = "tampered"
			break
		}
	}
	modified, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, modified, 0600); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(dir, "denied-receipt.json")
	if err := runValidateStageScopedBound(report, stage, denied); err == nil {
		t.Fatal("tampered identity accepted")
	}
	if _, err := os.Stat(denied); !os.IsNotExist(err) {
		t.Fatal("denied receipt written")
	}
}
