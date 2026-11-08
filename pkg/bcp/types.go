package bcp

import "time"

const ContractVersion = "bcp/0.4-durable-replay-v1"

type Risk string

const (
	RiskRead        Risk = "read"
	RiskMutate      Risk = "mutate"
	RiskHigh        Risk = "high"
	RiskDestructive Risk = "destructive"
)

type Operation struct {
	ID             string
	IdempotencyKey string
	ActorID        string
	Capability     string
	Target         string
	Action         string
	Risk           Risk
	Payload        []byte
}

type Result struct {
	OperationID string
	Status      string
	Code        string
	Output      []byte
	CreatedAt   time.Time
}

type ReplayItem struct {
	OperationID    string
	IdempotencyKey string
	Action         string
	Target         string
	Attempt        int
	State          string
}

type Grant struct {
	ID               string
	Subject          string
	Capability       string
	TargetPrefix     string
	Risks            []Risk
	NotBefore        time.Time
	ExpiresAt        time.Time
	OneTime          bool
	HighRiskApproved bool
	BoundOperationID string
	KeyID            string
	Signature        string
}

type OutboxItem struct {
	Seq         int64
	MessageID   string
	OperationID string
	Kind        string
	Body        []byte
	SentCount   int
	State       string
}

type Envelope struct {
	Version     string    `json:"version"`
	MessageID   string    `json:"message_id"`
	AgentID     string    `json:"agent_id"`
	SessionID   string    `json:"session_id"`
	Seq         int64     `json:"seq,omitempty"`
	Ack         int64     `json:"ack,omitempty"`
	Type        string    `json:"type"`
	OperationID string    `json:"operation_id,omitempty"`
	Body        []byte    `json:"body,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

type DeviceEntry struct {
	ID              string `json:"id"`
	Generation      string `json:"generation"`
	Fingerprint     string `json:"fingerprint"`
	RoutingEligible bool   `json:"routing_eligible"`
	PublisherDeny   bool   `json:"publisher_deny"`
	CreatedAt       string `json:"created_at,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

type ShadowReceipt struct {
	OperationID string    `json:"operation_id"`
	Decision    string    `json:"decision"`
	Code        string    `json:"code"`
	Executed    bool      `json:"executed"`
	ObservedAt  time.Time `json:"observed_at"`
}
