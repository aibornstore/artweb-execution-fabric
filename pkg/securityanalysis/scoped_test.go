package securityanalysis

import (
	"encoding/json"
	"strings"
	"testing"
)

const scopedFixture = `<nmaprun><host><address addr="192.0.2.40" addrtype="ipv4"/><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>`

func TestScopedIdentityDiffersAcrossProjectsAndNamespaces(t *testing.T) {
	report, err := Parse("nmap", []byte(scopedFixture))
	if err != nil {
		t.Fatal(err)
	}
	a, err := ProjectSTARTScoped(report, "project-a", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	same, err := ProjectSTARTScoped(report, "project-a", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ProjectSTARTScoped(report, "project-b", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ProjectSTARTScoped(report, "project-a", "namespace.b")
	if err != nil {
		t.Fatal(err)
	}
	ra, _ := json.Marshal(a)
	rs, _ := json.Marshal(same)
	if string(ra) != string(rs) {
		t.Fatal("scoped V2 not deterministic")
	}
	if len(a.Primitives) != len(b.Primitives) || len(a.Primitives) != len(c.Primitives) {
		t.Fatal("atom count changed")
	}
	for i := range a.Primitives {
		if a.Primitives[i].ID == b.Primitives[i].ID || a.Primitives[i].ID == c.Primitives[i].ID {
			t.Fatalf("cross-scope identity collision at %d", i)
		}
		if a.Primitives[i].ID != a.Primitives[i].CanonicalID {
			t.Fatal("canonical ID leaks unscoped identity")
		}
	}
	for _, env := range []STARTEnvelope{a, b, c} {
		if _, err := ValidateSTARTScopedAgainstReport(report, env); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScopedEdgesExistAndAreScoped(t *testing.T) {
	report, err := Parse("nmap", []byte(scopedFixture))
	if err != nil {
		t.Fatal(err)
	}
	env, err := ProjectSTARTScoped(report, "project-a", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[string]bool{}
	for _, a := range env.Primitives {
		if a.Type != "P4" {
			nodes[a.ID] = true
		}
	}
	var edges int
	for _, a := range env.Primitives {
		if a.Type == "P4" {
			edges++
			v := a.Value.(map[string]string)
			if !nodes[v["from"]] || !nodes[v["to"]] {
				t.Fatal("unscoped or dangling endpoint")
			}
			if !strings.HasPrefix(a.ID, "urn:security-analysis:scoped:v2:") {
				t.Fatal(a.ID)
			}
		}
	}
	if edges == 0 {
		t.Fatal("no relations")
	}
}

func TestScopedBoundaryRejectsLegacyAndForeignReferences(t *testing.T) {
	report, err := Parse("nmap", []byte(scopedFixture))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ProjectSTART(report, "project-a", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSTARTScopedAgainstReport(report, legacy); err == nil {
		t.Fatal("legacy downgrade accepted")
	}
	env, err := ProjectSTARTScoped(report, "project-a", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	// Clone through JSON to prevent mutation of the baseline's maps.
	raw, _ := json.Marshal(env)
	var other STARTEnvelope
	if err := json.Unmarshal(raw, &other); err != nil {
		t.Fatal(err)
	}
	for i := range other.Primitives {
		if other.Primitives[i].Type == "P4" {
			edge := other.Primitives[i].Value.(map[string]interface{})
			edge["to"] = "urn:security-analysis:scoped:v2:ffffffffffffffffffffffffffffffff"
			break
		}
	}
	if _, err := ValidateSTARTScopedAgainstReport(report, other); err == nil {
		t.Fatal("foreign edge accepted")
	}
	again, err := ProjectSTARTScoped(report, "project-a", "namespace.a")
	if err != nil {
		t.Fatal(err)
	}
	again.Primitives[0].CanonicalID = "urn:security-analysis:bad"
	if _, err := ValidateSTARTScopedAgainstReport(report, again); err == nil {
		t.Fatal("canonical identity forgery accepted")
	}
}
