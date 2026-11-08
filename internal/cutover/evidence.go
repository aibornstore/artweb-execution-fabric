package cutover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

var readonlyCapabilities = map[string]bool{
	"host.status@1": true, "system.info@1": true, "process.list@1": true,
	"fs.stat@1": true, "fs.list@1": true, "fs.read@1": true,
	"network.ping@1": true, "service.status@1": true,
}

func IsReadOnlyCapability(capability string) bool { return readonlyCapabilities[capability] }

func shaHex(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func normalizedKey(k Key) Key {
	k.MachineID = strings.TrimSpace(k.MachineID)
	k.Project = strings.TrimSpace(k.Project)
	k.Capability = strings.TrimSpace(k.Capability)
	k.Target = strings.TrimSpace(k.Target)
	return k
}
func validateKey(k Key) error {
	k = normalizedKey(k)
	if k.MachineID == "" || k.Project == "" || k.Capability == "" || k.Target == "" {
		return fmt.Errorf("machine, project, capability and target are required")
	}
	if !IsReadOnlyCapability(k.Capability) {
		return fmt.Errorf("capability %q is not in the read-only cutover surface", k.Capability)
	}
	return nil
}

type parsedEvidence struct {
	raw  []byte
	hash string
	at   time.Time
	rec  Evidence
}

func Evaluate(rawEvidence [][]byte, key Key, policy Policy, now time.Time) (PromotionReceipt, error) {
	key = normalizedKey(key)
	if err := validateKey(key); err != nil {
		return PromotionReceipt{}, err
	}
	if policy.MinUniqueFreshPass < 1 || policy.MinDistinctBoots < 1 || policy.FailureWindow < 1 || policy.MaxEvidenceAge <= 0 || policy.LeaseDuration <= 0 {
		return PromotionReceipt{}, fmt.Errorf("invalid promotion policy")
	}
	out := PromotionReceipt{Schema: PromotionSchema, GeneratedAt: now.UTC().Format(time.RFC3339Nano), Key: key, Decision: DecisionHoldShadow, RecommendedRoute: RouteShadow}
	add := func(name string, ok bool, detail string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
		}
		out.Checks = append(out.Checks, Check{Name: name, Status: status, Detail: detail})
	}
	seen := map[string]bool{}
	var items []parsedEvidence
	for i, raw := range rawEvidence {
		var e Evidence
		if err := json.Unmarshal(raw, &e); err != nil {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: decode: %w", i, err)
		}
		if e.Schema != EvidenceSchema {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: unsupported schema %q", i, e.Schema)
		}
		ek := normalizedKey(Key{MachineID: e.MachineID, Project: e.Project, Capability: e.Capability, Target: e.Target})
		if ek != key {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: target mismatch", i)
		}
		if e.Status != "PASS" && e.Status != "FAIL" {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: invalid status", i)
		}
		if strings.TrimSpace(e.CommandID) == "" || !validSHA256(strings.TrimSpace(e.ResultSHA256)) || strings.TrimSpace(e.EvidenceSource) != "relay-authenticated-command" {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: missing authenticated relay command anchor", i)
		}
		if strings.TrimSpace(e.BootID) == "" || strings.TrimSpace(e.AgentVersion) == "" {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: boot_id and agent_version required", i)
		}
		at, err := time.Parse(time.RFC3339Nano, e.GeneratedAt)
		if err != nil {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: generated_at: %w", i, err)
		}
		if at.After(now.Add(5 * time.Minute)) {
			return PromotionReceipt{}, fmt.Errorf("evidence %d: future timestamp", i)
		}
		h := shaHex(raw)
		if seen[h] {
			continue
		}
		seen[h] = true
		items = append(items, parsedEvidence{raw: raw, hash: h, at: at, rec: e})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	out.EvidenceCount = len(items)
	freshBoots := map[string]bool{}
	freshPass := 0
	stale := 0
	badAgent := 0
	for _, it := range items {
		age := now.Sub(it.at)
		fresh := age >= 0 && age <= policy.MaxEvidenceAge
		if age > policy.MaxEvidenceAge {
			stale++
		}
		if policy.RequireAgentPrefix != "" && !strings.HasPrefix(it.rec.AgentVersion, policy.RequireAgentPrefix) {
			badAgent++
		}
		if fresh && it.rec.Status == "PASS" {
			freshPass++
			freshBoots[it.rec.BootID] = true
		}
		out.Evidence = append(out.Evidence, EvidenceRef{SHA256: it.hash, GeneratedAt: it.rec.GeneratedAt, Status: it.rec.Status, CommandID: it.rec.CommandID, BootID: it.rec.BootID, AgentVersion: it.rec.AgentVersion})
	}
	out.FreshPassCount = freshPass
	out.DistinctFreshBoots = len(freshBoots)
	window := policy.FailureWindow
	if window > len(items) {
		window = len(items)
	}
	recentFail := false
	if window > 0 {
		for _, it := range items[len(items)-window:] {
			age := now.Sub(it.at)
			if age >= 0 && age <= policy.MaxEvidenceAge && it.rec.Status != "PASS" {
				recentFail = true
				break
			}
		}
	}
	add("unique_evidence", len(items) >= policy.MinUniqueFreshPass, fmt.Sprintf("have=%d need=%d", len(items), policy.MinUniqueFreshPass))
	add("fresh_pass_evidence", freshPass >= policy.MinUniqueFreshPass, fmt.Sprintf("have=%d need=%d stale=%d", freshPass, policy.MinUniqueFreshPass, stale))
	add("distinct_fresh_boots", len(freshBoots) >= policy.MinDistinctBoots, fmt.Sprintf("have=%d need=%d", len(freshBoots), policy.MinDistinctBoots))
	add("agent_version_policy", badAgent == 0, fmt.Sprintf("mismatches=%d required_prefix=%q", badAgent, policy.RequireAgentPrefix))
	add("recent_failure_window", !recentFail, fmt.Sprintf("window=%d", window))
	hashes := make([]string, 0, len(items))
	for _, it := range items {
		hashes = append(hashes, it.hash)
	}
	sort.Strings(hashes)
	out.EvidenceCorpusSHA256 = shaHex([]byte(strings.Join(hashes, "\n")))
	if recentFail {
		out.Decision = DecisionRecovery
		out.RecommendedRoute = RouteRecoveryFallback
		return out, nil
	}
	if len(items) >= policy.MinUniqueFreshPass && freshPass >= policy.MinUniqueFreshPass && len(freshBoots) >= policy.MinDistinctBoots && badAgent == 0 {
		out.Decision = DecisionBridgeEligible
		out.RecommendedRoute = RouteBridgePrimary
		out.LeaseValidUntil = now.UTC().Add(policy.LeaseDuration).Format(time.RFC3339Nano)
	}
	return out, nil
}
