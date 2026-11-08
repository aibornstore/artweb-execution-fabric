package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aibornstore/artweb-execution-fabric/internal/cutover"
	"github.com/aibornstore/artweb-execution-fabric/internal/identity"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
)

type completedJobOutput struct {
	Status    string             `json:"status"`
	State     string             `json:"state"`
	CommandID string             `json:"command_id"`
	Command   protocol.Command   `json:"command"`
	Result    protocol.JobResult `json:"result"`
}

func runEvidence(args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	jobPath := fs.String("job", "", "completed bridgectl JSON output")
	pubPath := fs.String("controller-public-key", "", "controller Ed25519 public key")
	project := fs.String("project", "GLOBAL", "project")
	out := fs.String("out", "", "evidence output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*jobPath) == "" || strings.TrimSpace(*pubPath) == "" || strings.TrimSpace(*out) == "" {
		return errors.New("--job, --controller-public-key and --out are required")
	}
	raw, err := os.ReadFile(*jobPath)
	if err != nil {
		return err
	}
	pub, err := identity.ReadPublicFile(*pubPath)
	if err != nil {
		return err
	}
	ev, err := evidenceFromCompletedJob(raw, pub, *project)
	if err != nil {
		return err
	}
	return writeEvidenceExclusive(*out, ev)
}

func evidenceFromCompletedJob(raw []byte, pub ed25519.PublicKey, project string) (cutover.Evidence, error) {
	raw, err := normalizeJSONEncoding(raw)
	if err != nil {
		return cutover.Evidence{}, err
	}
	var in completedJobOutput
	if err := json.Unmarshal(raw, &in); err != nil {
		return cutover.Evidence{}, fmt.Errorf("decode completed job: %w", err)
	}
	if in.Status != "PASS" || in.State != "completed" {
		return cutover.Evidence{}, errors.New("job is not completed PASS")
	}
	if in.CommandID == "" || in.Command.CommandID != in.CommandID || in.Result.CommandID != in.CommandID {
		return cutover.Evidence{}, errors.New("command id binding mismatch")
	}
	if in.Command.AgentID == "" || in.Command.AgentID != in.Result.AgentID {
		return cutover.Evidence{}, errors.New("agent id binding mismatch")
	}
	if in.Command.Operation.ID == "" || in.Command.Operation.ID != in.Result.OperationID {
		return cutover.Evidence{}, errors.New("operation id binding mismatch")
	}
	if !cutover.IsReadOnlyCapability(in.Command.Operation.Capability) {
		return cutover.Evidence{}, errors.New("capability is outside read-only cutover surface")
	}

	if strings.TrimSpace(in.Result.BootID) == "" || strings.TrimSpace(in.Result.AgentVersion) == "" {
		return cutover.Evidence{}, errors.New("worker provenance missing")
	}
	if in.Result.CreatedAt.IsZero() {
		return cutover.Evidence{}, errors.New("result timestamp missing")
	}
	if in.Result.CreatedAt.Before(in.Command.IssuedAt.Add(-30*time.Second)) ||
		in.Result.CreatedAt.After(in.Command.ExpiresAt.Add(30*time.Second)) {
		return cutover.Evidence{}, errors.New("result timestamp outside signed command window")
	}
	keyID := strings.TrimSpace(in.Command.ControllerKeyID)
	if keyID == "" || len(pub) != ed25519.PublicKeySize {
		return cutover.Evidence{}, errors.New("controller verification key missing")
	}
	verifier := protocol.CommandVerifier{Keys: map[string]ed25519.PublicKey{keyID: pub}}
	if err := verifier.Verify(in.Command, in.Command.IssuedAt); err != nil {
		return cutover.Evidence{}, fmt.Errorf("signed command verification failed: %w", err)
	}
	digest, err := in.Result.Digest()
	if err != nil {
		return cutover.Evidence{}, err
	}
	status := "FAIL"
	if in.Result.Status == "ok" {
		status = "PASS"
	}

	project = strings.TrimSpace(project)
	if project == "" {
		return cutover.Evidence{}, errors.New("project is required")
	}
	return cutover.Evidence{
		Schema:         cutover.EvidenceSchema,
		GeneratedAt:    in.Result.CreatedAt.UTC().Format(time.RFC3339Nano),
		MachineID:      in.Result.AgentID,
		Project:        project,
		Capability:     in.Command.Operation.Capability,
		Target:         in.Command.Operation.Target,
		Status:         status,
		CommandID:      in.CommandID,
		ResultSHA256:   digest,
		BootID:         in.Result.BootID,
		AgentVersion:   in.Result.AgentVersion,
		EvidenceSource: "relay-authenticated-command",
	}, nil
}

func normalizeJSONEncoding(raw []byte) ([]byte, error) {
	if len(raw) >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf {
		return raw[3:], nil
	}
	if len(raw) < 2 || !((raw[0] == 0xff && raw[1] == 0xfe) || (raw[0] == 0xfe && raw[1] == 0xff)) {
		return raw, nil
	}
	if (len(raw)-2)%2 != 0 {
		return nil, errors.New("invalid UTF-16 JSON byte length")
	}
	little := raw[0] == 0xff
	u16 := make([]uint16, 0, (len(raw)-2)/2)
	for i := 2; i < len(raw); i += 2 {
		if little {
			u16 = append(u16, binary.LittleEndian.Uint16(raw[i:i+2]))
		} else {
			u16 = append(u16, binary.BigEndian.Uint16(raw[i:i+2]))
		}
	}
	return []byte(string(utf16.Decode(u16))), nil
}

func writeEvidenceExclusive(path string, ev cutover.Evidence) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
