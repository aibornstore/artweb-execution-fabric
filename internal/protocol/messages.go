package protocol

type ChallengeMessage struct {
	Type      string    `json:"type"`
	Challenge Challenge `json:"challenge"`
}

type HelloMessage struct {
	Type  string     `json:"type"`
	Proof HelloProof `json:"proof"`
}

type HelloOKMessage struct {
	Type      string `json:"type"`
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
}
