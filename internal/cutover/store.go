package cutover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type stateEnvelope struct {
	Schema     string          `json:"schema"`
	Generation uint64          `json:"generation"`
	Payload    json.RawMessage `json:"payload"`
	SHA256     string          `json:"sha256"`
}

func checksum(payload []byte) string         { h := sha256.Sum256(payload); return hex.EncodeToString(h[:]) }
func slotPath(base string, slot byte) string { return fmt.Sprintf("%s.%c.json", base, slot) }
func readSlot(path string) (State, uint64, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, 0, false, nil
	}
	if err != nil {
		return State{}, 0, false, err
	}
	var env stateEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return State{}, 0, true, err
	}
	if env.Schema != StateSchema {
		return State{}, 0, true, fmt.Errorf("bad state schema")
	}
	var s State
	if err := json.Unmarshal(env.Payload, &s); err != nil {
		return State{}, 0, true, err
	}
	canonical, err := json.Marshal(normalizeState(s))
	if err != nil {
		return State{}, 0, true, err
	}
	if checksum(canonical) != env.SHA256 {
		return State{}, 0, true, fmt.Errorf("state checksum mismatch")
	}
	return normalizeState(s), env.Generation, true, nil
}
func normalizeRoute(route string) string {
	switch route {
	case LegacyRDCFallback:
		return RouteRecoveryFallback
	case RouteShadow, RouteBridgePrimary, RouteRecoveryFallback, RouteMaintenance:
		return route
	default:
		return RouteShadow
	}
}
func normalizeState(s State) State {
	if s.Entries == nil {
		s.Entries = []Entry{}
	}
	if s.History == nil {
		s.History = []Transition{}
	}
	for i := range s.Entries {
		s.Entries[i].Route = normalizeRoute(s.Entries[i].Route)
	}
	for i := range s.History {
		s.History[i].From = normalizeRoute(s.History[i].From)
		s.History[i].To = normalizeRoute(s.History[i].To)
	}
	return s
}
func Load(path string) (State, uint64, error) {
	a, ga, ea, erra := readSlot(slotPath(path, 'a'))
	b, gb, eb, errb := readSlot(slotPath(path, 'b'))
	va := ea && erra == nil
	vb := eb && errb == nil
	if va && vb {
		if gb > ga {
			return b, gb, nil
		}
		return a, ga, nil
	}
	if va {
		return a, ga, nil
	}
	if vb {
		return b, gb, nil
	}
	if !ea && !eb {
		return normalizeState(State{}), 0, nil
	}
	return State{}, 0, fmt.Errorf("cutover state has no valid slot: a=%v b=%v", erra, errb)
}
func writeNext(path string, generation uint64, state State) (uint64, error) {
	state = normalizeState(state)
	payload, err := json.Marshal(state)
	if err != nil {
		return generation, err
	}
	next := generation + 1
	env := stateEnvelope{Schema: StateSchema, Generation: next, Payload: payload, SHA256: checksum(payload)}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return generation, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return generation, err
	}
	slot := 'a'
	if next%2 == 0 {
		slot = 'b'
	}
	dst := slotPath(path, byte(slot))
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return generation, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return generation, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return generation, err
	}
	if err = f.Close(); err != nil {
		return generation, err
	}
	if err = os.Rename(tmp, dst); err != nil {
		return generation, err
	}
	ok = true
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return next, nil
}
