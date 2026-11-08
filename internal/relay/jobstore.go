package relay

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	_ "modernc.org/sqlite"
)

var (
	ErrJobNotFound       = errors.New("job not found")
	ErrJobConflict       = errors.New("command id conflicts with existing job")
	ErrJobResultConflict = errors.New("job already completed with different result")
)

type JobStore struct{ db *sql.DB }

func OpenJobStore(path string) (*JobStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &JobStore{db: db}
	if err := s.init(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *JobStore) Close() error { return s.db.Close() }

func (s *JobStore) init(ctx context.Context) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
		`CREATE TABLE IF NOT EXISTS jobs(
			command_id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL,
			command_json BLOB NOT NULL,
			command_digest TEXT NOT NULL,
			state TEXT NOT NULL,
			lease_until TEXT,
			result_json BLOB,
			result_digest TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS jobs_agent_state_created
		  ON jobs(agent_id,state,created_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("job store init: %w", err)
		}
	}
	return nil
}

func (s *JobStore) Create(ctx context.Context, cmd protocol.Command, now time.Time) (protocol.Job, bool, error) {
	digest, err := protocol.CommandDigest(cmd)
	if err != nil {
		return protocol.Job{}, false, err
	}
	raw, err := json.Marshal(cmd)
	if err != nil {
		return protocol.Job{}, false, err
	}
	now = now.UTC()
	ts := now.Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO jobs(command_id,agent_id,command_json,command_digest,state,created_at,updated_at)
		 VALUES(?,?,?,?, 'queued',?,?)`,
		cmd.CommandID, cmd.AgentID, raw, digest, ts, ts)
	if err == nil {
		return protocol.Job{Command: cmd, State: "queued", CreatedAt: now, UpdatedAt: now}, false, nil
	}

	existing, getErr := s.Get(ctx, cmd.CommandID)
	if getErr != nil {
		return protocol.Job{}, false, err
	}
	existingDigest, digErr := protocol.CommandDigest(existing.Command)
	if digErr != nil {
		return protocol.Job{}, false, digErr
	}
	if existingDigest != digest {
		return protocol.Job{}, false, ErrJobConflict
	}
	return existing, true, nil
}

func (s *JobStore) Get(ctx context.Context, commandID string) (protocol.Job, error) {
	var raw, resultRaw []byte
	var state, created, updated string
	var lease sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT command_json,state,lease_until,result_json,created_at,updated_at
		   FROM jobs WHERE command_id=?`, commandID).
		Scan(&raw, &state, &lease, &resultRaw, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.Job{}, ErrJobNotFound
	}
	if err != nil {
		return protocol.Job{}, err
	}
	var cmd protocol.Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return protocol.Job{}, err
	}
	job := protocol.Job{Command: cmd, State: state}
	job.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return protocol.Job{}, err
	}
	job.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return protocol.Job{}, err
	}
	if lease.Valid {
		t, err := time.Parse(time.RFC3339Nano, lease.String)
		if err != nil {
			return protocol.Job{}, err
		}
		job.LeaseUntil = &t
	}
	if len(resultRaw) != 0 {
		var result protocol.JobResult
		if err := json.Unmarshal(resultRaw, &result); err != nil {
			return protocol.Job{}, err
		}
		job.Result = &result
	}
	return job, nil
}

func (s *JobStore) LeaseNext(ctx context.Context, agentID string, now time.Time, lease time.Duration) (*protocol.Job, error) {
	if agentID == "" {
		return nil, errors.New("agent id is required")
	}
	if lease <= 0 {
		lease = 30 * time.Second
	}
	now = now.UTC()
	nowText := now.Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var activeLeases int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM jobs
		   WHERE agent_id=? AND state='leased' AND lease_until IS NOT NULL
		     AND julianday(lease_until)>julianday(?)`,
		agentID, nowText).Scan(&activeLeases); err != nil {
		return nil, err
	}
	if activeLeases != 0 {
		return nil, nil
	}

	var commandID string
	err = tx.QueryRowContext(ctx,
		`SELECT command_id FROM jobs
		   WHERE agent_id=? AND (
		     state='queued' OR
		     (state='leased' AND lease_until IS NOT NULL AND julianday(lease_until)<=julianday(?))
		   )
		   ORDER BY julianday(created_at),command_id LIMIT 1`,
		agentID, nowText).Scan(&commandID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	until := now.Add(lease).Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx,
		`UPDATE jobs SET state='leased',lease_until=?,updated_at=?
		   WHERE command_id=? AND (
		     state='queued' OR
		     (state='leased' AND lease_until IS NOT NULL AND julianday(lease_until)<=julianday(?))
		   )`,
		until, nowText, commandID, nowText)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("job lease race")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	job, err := s.Get(ctx, commandID)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *JobStore) Complete(ctx context.Context, agentID string, result protocol.JobResult, now time.Time) error {
	if agentID == "" || result.CommandID == "" || result.OperationID == "" {
		return errors.New("job result identity is incomplete")
	}
	digest, err := result.Digest()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	now = now.UTC()
	ts := now.Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var storedAgent, state string
	var commandRaw, storedResult []byte
	var digestNull sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT agent_id,state,command_json,result_json,result_digest
		   FROM jobs WHERE command_id=?`, result.CommandID).
		Scan(&storedAgent, &state, &commandRaw, &storedResult, &digestNull)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJobNotFound
	}
	if err != nil {
		return err
	}
	if storedAgent != agentID || result.AgentID != agentID {
		return errors.New("job result agent mismatch")
	}
	var cmd protocol.Command
	if err := json.Unmarshal(commandRaw, &cmd); err != nil {
		return err
	}
	if cmd.Operation.ID != result.OperationID {
		return errors.New("job result operation mismatch")
	}
	if state == "completed" {
		if digestNull.Valid && digestNull.String == digest {
			return nil
		}
		return ErrJobResultConflict
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE jobs SET state='completed',lease_until=NULL,result_json=?,result_digest=?,updated_at=?
		   WHERE command_id=?`,
		raw, digest, ts, result.CommandID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
