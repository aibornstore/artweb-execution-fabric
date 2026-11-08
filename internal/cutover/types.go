package cutover

import "time"

const (
	EvidenceSchema   = "artweb.bridge-authenticated-evidence/v1"
	PromotionSchema  = "artweb.bridge-capability-promotion/v2"
	StateSchema      = "artweb.bridge-capability-routing-state/v2"
	TransitionSchema = "artweb.bridge-capability-routing-transition/v2"
	ProfileSchema    = "artweb.bridge-cutover-profile/v1"
)

const (
	RouteShadow           = "SHADOW"
	RouteBridgePrimary    = "BRIDGE_NATIVE_PRIMARY"
	RouteRecoveryFallback = "RECOVERY_FALLBACK"
	RouteMaintenance      = "MAINTENANCE"
	LegacyRDCFallback     = "RDC_FALLBACK"
)

const (
	// Fail-closed routing policies (S3 enforcement)
	PolicyRequireExplicitDeviceId        = "require_explicit_device_id"
	PolicyRequireHardwareFingerprint     = "require_hardware_fingerprint"
	PolicyNeverFallbackToFirstOnline     = "never_fallback_to_first_online"
	PolicyWrongTargetMustFailClosed      = "wrong_target_must_fail_closed"
	PolicyOfflineTargetMustFailClosed    = "offline_target_must_fail_closed"
	PolicyStaleDeviceRecordMustNotBecomeCanonical = "stale_device_record_must_not_become_canonical"
	PolicyPublisherExcluded              = "publisher_excluded"
	PolicyStatefulCrossDeviceSessions    = "stateful_cross_device_sessions"
)

const (
	DecisionHoldShadow     = "HOLD_SHADOW"
	DecisionBridgeEligible = "BRIDGE_PRIMARY_ELIGIBLE"
	DecisionRecovery       = "RECOVERY_REQUIRED"
	DecisionMaintenance    = "MAINTENANCE_REQUIRED"
)

type Key struct {
	MachineID  string `json:"machine_id"`
	Project    string `json:"project"`
	Capability string `json:"capability"`
	Target     string `json:"target"`
}

type Evidence struct {
	Schema         string `json:"schema"`
	GeneratedAt    string `json:"generated_at"`
	MachineID      string `json:"machine_id"`
	Project        string `json:"project"`
	Capability     string `json:"capability"`
	Target         string `json:"target"`
	Status         string `json:"status"`
	CommandID      string `json:"command_id"`
	ResultSHA256   string `json:"result_sha256"`
	BootID         string `json:"boot_id"`
	AgentVersion   string `json:"agent_version"`
	EvidenceSource string `json:"evidence_source"`
}

type Policy struct {
	MinUniqueFreshPass int           `json:"min_unique_fresh_pass"`
	MinDistinctBoots   int           `json:"min_distinct_boots"`
	MaxEvidenceAge     time.Duration `json:"-"`
	FailureWindow      int           `json:"failure_window"`
	LeaseDuration      time.Duration `json:"-"`
	RequireAgentPrefix string        `json:"require_agent_prefix,omitempty"`
}

func DefaultPolicy() Policy {
	return Policy{
		MinUniqueFreshPass: 5,
		MinDistinctBoots:   2,
		MaxEvidenceAge:     7 * 24 * time.Hour,
		FailureWindow:      3,
		LeaseDuration:      24 * time.Hour,
	}
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type EvidenceRef struct {
	SHA256       string `json:"sha256"`
	GeneratedAt  string `json:"generated_at"`
	Status       string `json:"status"`
	CommandID    string `json:"command_id"`
	BootID       string `json:"boot_id"`
	AgentVersion string `json:"agent_version"`
}

type PromotionReceipt struct {
	Schema               string        `json:"schema"`
	GeneratedAt          string        `json:"generated_at"`
	Key                  Key           `json:"key"`
	Decision             string        `json:"decision"`
	RecommendedRoute     string        `json:"recommended_route"`
	EvidenceCount        int           `json:"evidence_count"`
	FreshPassCount       int           `json:"fresh_pass_count"`
	DistinctFreshBoots   int           `json:"distinct_fresh_boots"`
	EvidenceCorpusSHA256 string        `json:"evidence_corpus_sha256"`
	LeaseValidUntil      string        `json:"lease_valid_until,omitempty"`
	Checks               []Check       `json:"checks"`
	Evidence             []EvidenceRef `json:"evidence"`
}

type Entry struct {
	Key
	Route                string `json:"route"`
	UpdatedAt            string `json:"updated_at"`
	Reason               string `json:"reason"`
	EvidenceCorpusSHA256 string `json:"evidence_corpus_sha256,omitempty"`
	LeaseValidUntil      string `json:"lease_valid_until,omitempty"`
}

type Transition struct {
	At                   string `json:"at"`
	Key                  Key    `json:"key"`
	From                 string `json:"from"`
	To                   string `json:"to"`
	Reason               string `json:"reason"`
	EvidenceCorpusSHA256 string `json:"evidence_corpus_sha256,omitempty"`
}

type State struct {
	Entries []Entry      `json:"entries"`
	History []Transition `json:"history,omitempty"`
}

type TransitionReceipt struct {
	Schema               string `json:"schema"`
	GeneratedAt          string `json:"generated_at"`
	Key                  Key    `json:"key"`
	PromotionDecision    string `json:"promotion_decision"`
	PreviousRoute        string `json:"previous_route"`
	Route                string `json:"route"`
	Changed              bool   `json:"changed"`
	StateGeneration      uint64 `json:"state_generation"`
	EvidenceCorpusSHA256 string `json:"evidence_corpus_sha256,omitempty"`
	LeaseValidUntil      string `json:"lease_valid_until,omitempty"`
	Reason               string `json:"reason"`
}

type ProfileTarget struct {
	Capability string `json:"capability"`
	Target     string `json:"target"`
}

type ProfileResult struct {
	Schema         string              `json:"schema"`
	GeneratedAt    string              `json:"generated_at"`
	Profile        string              `json:"profile"`
	MachineID      string              `json:"machine_id"`
	Project        string              `json:"project"`
	BridgePrimary  bool                `json:"bridge_primary"`
	RDCIndependent bool                `json:"rdc_independent"`
	Decision       string              `json:"decision"`
	Capabilities   []ProfileCapability `json:"capabilities"`
}

type ProfileCapability struct {
	Capability string `json:"capability"`
	Target     string `json:"target"`
	Route      string `json:"route"`
	Reason     string `json:"reason"`
}
