package securityanalysis

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ValidateSTARTShadow checks the integrity of an existing candidate START/REAF
// staging envelope. It does NOT execute REAF, authenticate a scanner export,
// or permit external operations. The original START v0.1 validator remains
// responsible for the canonical envelope syntax; this guard adds the missing
// structural edge and source-reference checks without changing its output.
func ValidateSTARTShadow(envelope STARTEnvelope) error {
	if !namespaceID.MatchString(envelope.ProjectID) || !namespaceID.MatchString(envelope.Namespace) {
		return errors.New("project/namespace identifier is invalid")
	}
	if strings.TrimSpace(envelope.Purpose) == "" {
		return errors.New("purpose missing")
	}
	if envelope.Authority.ExecuteExternal {
		return errors.New("external execution is not allowed in analysis staging")
	}
	if len(envelope.Sources) != 1 {
		return errors.New("analysis staging must reference exactly one source")
	}
	source := envelope.Sources[0]
	if !strings.HasPrefix(source, "sha256:") || len(source) != 71 {
		return errors.New("source reference must be an explicit SHA-256")
	}
	if _, err := hex.DecodeString(source[7:]); err != nil {
		return fmt.Errorf("invalid source digest: %w", err)
	}
	if len(envelope.Primitives) < 8 || len(envelope.Primitives) > MaxFindings*6+10 {
		return errors.New("invalid staging primitive count")
	}
	types := map[string]bool{}
	ids := map[string]bool{}
	nodes := map[string]bool{}
	relations := []STARTAtom{}
	for _, atom := range envelope.Primitives {
		if atom.ID == "" || atom.CanonicalID == "" || atom.Context == "" || atom.Value == nil {
			return errors.New("incomplete staging primitive")
		}
		if atom.Namespace != envelope.Namespace || atom.Provenance.Source != source {
			return fmt.Errorf("cross-namespace or cross-source primitive: %s", atom.ID)
		}
		if ids[atom.ID] {
			return fmt.Errorf("duplicate primitive: %s", atom.ID)
		}
		ids[atom.ID] = true
		switch atom.Type {
		case "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8":
			types[atom.Type] = true
		default:
			return fmt.Errorf("invalid primitive type: %s", atom.Type)
		}
		if atom.Type == "P4" {
			relations = append(relations, atom)
		} else {
			nodes[atom.ID] = true
		}
	}
	if len(types) != 8 {
		return fmt.Errorf("missing P1-P8 primitive types: found %d", len(types))
	}
	if len(relations) == 0 {
		return errors.New("no typed relations")
	}
	for _, relation := range relations {
		from, to, predicate, ok := relationFields(relation.Value)
		if !ok || from == "" || to == "" || predicate == "" {
			return fmt.Errorf("malformed relation: %s", relation.ID)
		}
		if !nodes[from] || !nodes[to] {
			return fmt.Errorf("dangling relation %s: from=%s to=%s", relation.ID, from, to)
		}
	}
	return nil
}

func relationFields(value any) (from, to, predicate string, ok bool) {
	switch m := value.(type) {
	case map[string]string:
		return m["from"], m["to"], m["predicate"], true
	case map[string]any:
		a, aa := m["from"].(string)
		b, bb := m["to"].(string)
		c, cc := m["predicate"].(string)
		return a, b, c, aa && bb && cc
	default:
		return "", "", "", false
	}
}

// STARTGuardReceipt is a local structural validation result, not REAF MAIN ACK.
type STARTGuardReceipt struct {
	Schema            string `json:"schema"`
	Status            string `json:"status"`
	EnvelopeSHA256    string `json:"envelope_sha256"`
	ProjectID         string `json:"project_id"`
	Namespace         string `json:"namespace"`
	Source            string `json:"source"`
	PrimitiveCount    int    `json:"primitive_count"`
	RelationCount     int    `json:"relation_count"`
	ExternalExecution bool   `json:"external_execution"`
}

func ReadbackSTARTShadow(envelope STARTEnvelope) (STARTGuardReceipt, error) {
	if err := ValidateSTARTShadow(envelope); err != nil {
		return STARTGuardReceipt{}, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return STARTGuardReceipt{}, err
	}
	count := 0
	for _, atom := range envelope.Primitives {
		if atom.Type == "P4" {
			count++
		}
	}
	return STARTGuardReceipt{Schema: "security.analysis-start-guard/v1", Status: "STRUCTURAL_VALIDATION_ONLY",
		EnvelopeSHA256: sha256Hex(raw), ProjectID: envelope.ProjectID, Namespace: envelope.Namespace,
		Source: envelope.Sources[0], PrimitiveCount: len(envelope.Primitives), RelationCount: count,
		ExternalExecution: false}, nil
}
