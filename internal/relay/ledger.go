package relay

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

var (
	ErrSequenceGap      = errors.New("relay sequence gap")
	ErrSequenceConflict = errors.New("relay sequence conflict")
)

type ledgerRecord struct {
	AgentID    string    `json:"agent_id"`
	SessionID  string    `json:"session_id"`
	Seq        int64     `json:"seq"`
	MessageID  string    `json:"message_id"`
	Digest     string    `json:"digest"`
	RecordedAt time.Time `json:"recorded_at"`
}

type Ledger struct {
	mu   sync.Mutex
	path string
	last map[string]ledgerRecord
}

func OpenLedger(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	l := &Ledger{path: path, last: make(map[string]ledgerRecord)}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		var r ledgerRecord
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			f.Close()
			return nil, err
		}
		key := sessionKey(r.AgentID, r.SessionID)
		if prev, ok := l.last[key]; !ok || r.Seq > prev.Seq {
			l.last[key] = r
		}
	}
	err = s.Err()
	f.Close()
	if err != nil {
		return nil, err
	}
	return l, nil
}

func sessionKey(agentID, sessionID string) string { return agentID + "\x00" + sessionID }

func envelopeDigest(env bcp.Envelope) (string, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (l *Ledger) Record(env bcp.Envelope) (int64, error) {
	if env.AgentID == "" || env.SessionID == "" || env.Seq <= 0 || env.MessageID == "" {
		return 0, errors.New("incomplete envelope identity")
	}
	digest, err := envelopeDigest(env)
	if err != nil {
		return 0, err
	}
	key := sessionKey(env.AgentID, env.SessionID)
	l.mu.Lock()
	defer l.mu.Unlock()
	prev, ok := l.last[key]
	if ok {
		if env.Seq < prev.Seq {
			return prev.Seq, nil
		}
		if env.Seq == prev.Seq {
			if env.MessageID != prev.MessageID || digest != prev.Digest {
				return 0, ErrSequenceConflict
			}
			return prev.Seq, nil
		}
		if env.Seq != prev.Seq+1 {
			return 0, ErrSequenceGap
		}
	} else if env.Seq != 1 {
		return 0, ErrSequenceGap
	}
	r := ledgerRecord{AgentID: env.AgentID, SessionID: env.SessionID, Seq: env.Seq, MessageID: env.MessageID, Digest: digest, RecordedAt: time.Now().UTC()}
	line, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 0, err
	}
	if _, err = f.Write(append(line, '\n')); err != nil {
		f.Close()
		return 0, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return 0, err
	}
	if err = f.Close(); err != nil {
		return 0, err
	}
	l.last[key] = r
	return r.Seq, nil
}
