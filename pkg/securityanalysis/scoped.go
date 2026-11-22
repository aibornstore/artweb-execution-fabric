package securityanalysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	ScopedStageSchema = "security.analysis-start-scoped-binding/v1"
	scopedStageMarker = "[scope-bound-v2]"
)

// ProjectSTARTScoped preserves the original START_REAF_INPUT_V0.1 envelope
// contract while scoping every atom identity and P4 endpoint to the exact
// project AND namespace. Old ProjectSTART and SealPacket output is unchanged.
// This is candidate staging only; it does not write to any graph store.
func ProjectSTARTScoped(report Report, projectID, namespace string) (STARTEnvelope, error) {
	env, err := ProjectSTART(report, projectID, namespace)
	if err != nil {
		return STARTEnvelope{}, err
	}
	remap := make(map[string]string, len(env.Primitives))
	for _, atom := range env.Primitives {
		newID := scopeIdentity(env.ProjectID, env.Namespace, atom.ID)
		if _, ok := remap[atom.ID]; ok {
			return STARTEnvelope{}, errors.New("duplicate unscoped atom identity")
		}
		remap[atom.ID] = newID
	}
	for i := range env.Primitives {
		atom := &env.Primitives[i]
		oldID := atom.ID
		atom.ID = remap[oldID]
		// Keep no unsalted identifiers in the canonical_id field: otherwise
		// independent project instances could be correlated by global IDs.
		atom.CanonicalID = atom.ID
		atom.Context += " " + scopedStageMarker
		if atom.Type == "P4" {
			// ProjectSTART currently uses map[string]string for edges.
			edge, ok := atom.Value.(map[string]string)
			if !ok {
				return STARTEnvelope{}, fmt.Errorf("unexpected P4 representation for %s", oldID)
			}
			from, fromOK := remap[edge["from"]]
			to, toOK := remap[edge["to"]]
			if !fromOK || !toOK {
				return STARTEnvelope{}, errors.New("P4 endpoint outside supplied project graph")
			}
			atom.Value = map[string]string{"from": from, "to": to, "predicate": edge["predicate"]}
		}
	}
	sort.Slice(env.Primitives, func(i, j int) bool { return env.Primitives[i].ID < env.Primitives[j].ID })
	if err := ValidateSTARTShadow(env); err != nil {
		return STARTEnvelope{}, err
	}
	return env, nil
}

func scopeIdentity(projectID, namespace, globalID string) string {
	// Length-prefixed encoding avoids separator-ambiguity and ensures names
	// cannot impersonate another project through concatenation.
	msg := fmt.Sprintf("v2:%d:%s%d:%s%d:%s", len(projectID), projectID, len(namespace), namespace, len(globalID), globalID)
	sum := sha256.Sum256([]byte(msg))
	return "urn:security-analysis:scoped:v2:" + hex.EncodeToString(sum[:16])
}

// ValidateSTARTScopedAgainstReport requires a V2-scoped projection exactly.
// The legacy V1 report-bound validator remains available as a separate path.
func ValidateSTARTScopedAgainstReport(report Report, env STARTEnvelope) (STARTGuardReceipt, error) {
	expected, err := ProjectSTARTScoped(report, env.ProjectID, env.Namespace)
	if err != nil {
		return STARTGuardReceipt{}, err
	}
	if err := ValidateSTARTShadow(env); err != nil {
		return STARTGuardReceipt{}, err
	}
	for _, a := range env.Primitives {
		if a.ID != a.CanonicalID {
			return STARTGuardReceipt{}, errors.New("scoped canonical_id mismatch")
		}
		if len(a.Context) < len(scopedStageMarker) || a.Context[len(a.Context)-len(scopedStageMarker):] != scopedStageMarker {
			return STARTGuardReceipt{}, errors.New("missing scoped-v2 context marker")
		}
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return STARTGuardReceipt{}, err
	}
	got, err := json.Marshal(env)
	if err != nil {
		return STARTGuardReceipt{}, err
	}
	if !bytes.Equal(want, got) {
		return STARTGuardReceipt{}, errors.New("scoped graph is not the canonical report-derived projection")
	}
	receipt, err := ReadbackSTARTShadow(env)
	if err != nil {
		return STARTGuardReceipt{}, err
	}
	receipt.Schema = ScopedStageSchema
	receipt.Status = "REPORT_NAMESPACE_SCOPED_STRUCTURAL_ONLY"
	return receipt, nil
}
