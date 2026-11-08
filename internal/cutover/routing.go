package cutover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func keyEqual(a, b Key) bool {
	return a.MachineID == b.MachineID && a.Project == b.Project && a.Capability == b.Capability && strings.EqualFold(a.Target, b.Target)
}
func entryIndex(s State, k Key) int {
	for i := range s.Entries {
		if keyEqual(s.Entries[i].Key, k) {
			return i
		}
	}
	return -1
}

type DeviceLookup interface {
	GetDevice(id string) (DeviceEntry, error)
}

type DeviceEntry struct {
	ID              string
	Generation      string
	Fingerprint     string
	RoutingEligible bool
	PublisherDeny   bool
}

func Resolve(path string, key Key, now time.Time, deviceLookup DeviceLookup) (Entry, bool, uint64, error) {
	key = normalizedKey(key)
	if err := validateKey(key); err != nil {
		return Entry{}, false, 0, err
	}
	s, gen, err := Load(path)
	if err != nil {
		return Entry{}, false, gen, err
	}
	i := entryIndex(s, key)
	if i < 0 {
		return Entry{Key: key, Route: RouteShadow, Reason: "default route"}, false, gen, nil
	}
	e := s.Entries[i]
	e.Route = normalizeRoute(e.Route)

	// Maintenance takes precedence over all other routes
	if e.Route == RouteMaintenance {
		return e, true, gen, nil
	}

	// S3: Check device eligibility and publisher deny
	if deviceLookup != nil {
		dev, err := deviceLookup.GetDevice(key.MachineID)
		if err == nil {
			if dev.PublisherDeny {
				return Entry{}, false, gen, fmt.Errorf("device %s is publisher-denied", key.MachineID)
			}
			if !dev.RoutingEligible {
				return Entry{}, false, gen, fmt.Errorf("device %s is not routing eligible", key.MachineID)
			}
		}
	}

	if e.Route == RouteBridgePrimary {
		until, err := time.Parse(time.RFC3339Nano, e.LeaseValidUntil)
		if err != nil || !now.Before(until) {
			// S3: Expired lease REJECTS instead of falling back to recovery
			return Entry{}, false, gen, fmt.Errorf("lease expired for %s", key.MachineID)
		}
	}
	return e, true, gen, nil
}

func Apply(path string, rawPromotion []byte, now time.Time) (TransitionReceipt, error) {
	if strings.TrimSpace(path) == "" {
		return TransitionReceipt{}, fmt.Errorf("routing state path required")
	}
	var p PromotionReceipt
	if err := json.Unmarshal(rawPromotion, &p); err != nil {
		return TransitionReceipt{}, fmt.Errorf("decode promotion: %w", err)
	}
	if p.Schema != PromotionSchema {
		return TransitionReceipt{}, fmt.Errorf("unsupported promotion schema %q", p.Schema)
	}
	p.Key = normalizedKey(p.Key)
	if err := validateKey(p.Key); err != nil {
		return TransitionReceipt{}, err
	}
	generated, err := time.Parse(time.RFC3339Nano, p.GeneratedAt)
	if err != nil {
		return TransitionReceipt{}, err
	}
	if generated.After(now.Add(5 * time.Minute)) {
		return TransitionReceipt{}, fmt.Errorf("promotion is from the future")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return TransitionReceipt{}, err
	}
	lk, err := acquireLock(path + ".lock")
	if err != nil {
		return TransitionReceipt{}, err
	}
	defer lk.Close()
	s, gen, err := Load(path)
	if err != nil {
		return TransitionReceipt{}, err
	}
	idx := entryIndex(s, p.Key)
	current := Entry{Key: p.Key, Route: RouteShadow, Reason: "default route"}
	if idx >= 0 {
		current = s.Entries[idx]
	}
	current.Route = normalizeRoute(current.Route)
	var currentAt time.Time
	if current.UpdatedAt != "" {
		currentAt, _ = time.Parse(time.RFC3339Nano, current.UpdatedAt)
	}
	next := current.Route
	reason := ""
	lease := current.LeaseValidUntil
	corpus := current.EvidenceCorpusSHA256
	switch p.Decision {
	case DecisionRecovery:
		next = RouteRecoveryFallback
		reason = "recent authenticated Bridge failure requires recovery"
		lease = ""
		corpus = p.EvidenceCorpusSHA256
	case DecisionHoldShadow:
		if current.Route == RouteRecoveryFallback {
			next = RouteRecoveryFallback
			reason = "shadow hold cannot clear active recovery"
		} else {
			next = RouteShadow
			reason = "evidence is insufficient for Bridge primary"
		}
		lease = ""
		corpus = p.EvidenceCorpusSHA256
	case DecisionBridgeEligible:
		until, err := time.Parse(time.RFC3339Nano, p.LeaseValidUntil)
		if err != nil || !until.After(now) {
			return TransitionReceipt{}, fmt.Errorf("eligible promotion requires a future evidence lease")
		}
		if current.Route == RouteRecoveryFallback && !currentAt.IsZero() && !generated.After(currentAt) {
			next = RouteRecoveryFallback
			reason = "stale eligibility cannot clear newer recovery"
			break
		}
		next = RouteBridgePrimary
		reason = "fresh authenticated Bridge evidence satisfies cutover gate"
		if current.Route == RouteBridgePrimary && current.EvidenceCorpusSHA256 == p.EvidenceCorpusSHA256 && current.LeaseValidUntil != "" {
			lease = current.LeaseValidUntil
			reason = "same evidence corpus cannot renew existing Bridge lease"
		} else {
			lease = p.LeaseValidUntil
		}
		corpus = p.EvidenceCorpusSHA256
	case DecisionMaintenance:
		next = RouteMaintenance
		reason = "device under maintenance"
		lease = ""
		corpus = p.EvidenceCorpusSHA256
	default:
		return TransitionReceipt{}, fmt.Errorf("unsupported promotion decision %q", p.Decision)
	}
	changed := next != current.Route || lease != current.LeaseValidUntil || corpus != current.EvidenceCorpusSHA256
	updated := current
	updated.Key = p.Key
	updated.Route = next
	updated.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	updated.Reason = reason
	updated.LeaseValidUntil = lease
	updated.EvidenceCorpusSHA256 = corpus
	if idx >= 0 {
		s.Entries[idx] = updated
	} else {
		s.Entries = append(s.Entries, updated)
	}
	if changed {
		s.History = append(s.History, Transition{At: updated.UpdatedAt, Key: p.Key, From: current.Route, To: next, Reason: reason, EvidenceCorpusSHA256: corpus})
		if len(s.History) > 1000 {
			s.History = append([]Transition(nil), s.History[len(s.History)-1000:]...)
		}
	}
	newGen := gen
	if changed {
		newGen, err = writeNext(path, gen, s)
		if err != nil {
			return TransitionReceipt{}, err
		}
	}
	return TransitionReceipt{Schema: TransitionSchema, GeneratedAt: now.UTC().Format(time.RFC3339Nano), Key: p.Key, PromotionDecision: p.Decision, PreviousRoute: current.Route, Route: next, Changed: changed, StateGeneration: newGen, EvidenceCorpusSHA256: corpus, LeaseValidUntil: lease, Reason: reason}, nil
}
