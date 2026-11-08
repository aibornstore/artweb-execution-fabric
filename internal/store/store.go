package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// The bridge journal is a correctness boundary, not a throughput database.
	// One connection keeps per-connection PRAGMAs consistent and serializes
	// one-time grant consumption deterministically.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if err := s.init(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init(ctx context.Context) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000",
		`CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,idempotency_key TEXT NOT NULL UNIQUE,actor_id TEXT NOT NULL,capability TEXT NOT NULL,target TEXT NOT NULL,action TEXT NOT NULL,risk TEXT NOT NULL,payload BLOB,state TEXT NOT NULL DEFAULT 'pending',attempt INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL) STRICT`,
		`CREATE TABLE IF NOT EXISTS results(operation_id TEXT PRIMARY KEY REFERENCES operations(id),status TEXT NOT NULL,code TEXT NOT NULL,output BLOB,created_at TEXT NOT NULL) STRICT`,
		`CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT,kind TEXT NOT NULL,body BLOB,created_at TEXT NOT NULL) STRICT`,
		`CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,subject TEXT NOT NULL,capability TEXT NOT NULL,target_prefix TEXT NOT NULL,risks_json TEXT NOT NULL,not_before TEXT NOT NULL,expires_at TEXT NOT NULL,one_time INTEGER NOT NULL,high_risk_approved INTEGER NOT NULL,bound_operation_id TEXT,key_id TEXT NOT NULL,signature TEXT NOT NULL,consumed_by_operation_id TEXT,consumed_at TEXT,created_at TEXT NOT NULL) STRICT`,
		`CREATE TABLE IF NOT EXISTS outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT NOT NULL UNIQUE,operation_id TEXT,kind TEXT NOT NULL,body BLOB,state TEXT NOT NULL DEFAULT 'pending',sent_count INTEGER NOT NULL DEFAULT 0,last_sent_at TEXT,acked_at TEXT,created_at TEXT NOT NULL) STRICT`,
		`CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,generation TEXT,fingerprint TEXT,routing_eligible INTEGER,publisher_deny INTEGER,created_at TEXT,updated_at TEXT) STRICT`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("init %q: %w", q, err)
		}
	}
	return nil
}
func (s *Store) BeginOperation(ctx context.Context, op bcp.Operation) (bool, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO operations(id,idempotency_key,actor_id,capability,target,action,risk,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, op.ID, op.IdempotencyKey, op.ActorID, op.Capability, op.Target, op.Action, string(op.Risk), op.Payload, now, now)
	if err == nil {
		return true, tx.Commit()
	}
	var id, actor, capability, target, action, risk string
	var payload []byte
	e := tx.QueryRowContext(ctx, `SELECT id,actor_id,capability,target,action,risk,payload FROM operations WHERE idempotency_key=?`, op.IdempotencyKey).
		Scan(&id, &actor, &capability, &target, &action, &risk, &payload)
	if e != nil {
		return false, err
	}
	if id != op.ID || actor != op.ActorID || capability != op.Capability || target != op.Target ||
		action != op.Action || risk != string(op.Risk) || !bytes.Equal(payload, op.Payload) {
		return false, ErrIdempotencyConflict
	}
	return false, nil
}
func (s *Store) Complete(ctx context.Context, r bcp.Result) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if !r.CreatedAt.IsZero() {
		now = r.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO results(operation_id,status,code,output,created_at) VALUES(?,?,?,?,?)`, r.OperationID, r.Status, r.Code, r.Output, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE operations SET state='done',updated_at=? WHERE id=?", now, r.OperationID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) GetResult(ctx context.Context, operationID string) (bcp.Result, error) {
	var r bcp.Result
	var created string
	err := s.db.QueryRowContext(ctx,
		`SELECT operation_id,status,code,output,created_at FROM results WHERE operation_id=?`,
		operationID,
	).Scan(&r.OperationID, &r.Status, &r.Code, &r.Output, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return bcp.Result{}, ErrResultNotFound
	}
	if err != nil {
		return bcp.Result{}, err
	}
	r.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return bcp.Result{}, err
	}
	return r, nil
}

func (s *Store) RecoverPending(ctx context.Context) ([]bcp.ReplayItem, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,idempotency_key,action,target,attempt,state FROM operations WHERE state!='done' ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bcp.ReplayItem
	for rows.Next() {
		var x bcp.ReplayItem
		if err := rows.Scan(&x.OperationID, &x.IdempotencyKey, &x.Action, &x.Target, &x.Attempt, &x.State); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) MarkUncertain(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE operations SET state='uncertain',attempt=attempt+1,updated_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return errors.New("operation not found")
	}
	return nil
}

var (
	ErrIdempotencyConflict = errors.New("idempotency key conflicts with existing operation")
	ErrResultNotFound      = errors.New("operation result not found")
	ErrGrantNotFound       = errors.New("grant not found")
	ErrGrantConsumed       = errors.New("one-time grant already consumed")
	ErrOutboxConflict      = errors.New("outbox message id conflict")
	ErrAckUnsent           = errors.New("ack covers unsent message")
	ErrDeviceNotFound      = errors.New("device not found")
)

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) PutGrant(ctx context.Context, g bcp.Grant) error {
	risks, err := json.Marshal(g.Risks)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grants(id,subject,capability,target_prefix,risks_json,not_before,expires_at,one_time,high_risk_approved,bound_operation_id,key_id,signature,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.Subject, g.Capability, g.TargetPrefix, string(risks),
		g.NotBefore.UTC().Format(time.RFC3339Nano), g.ExpiresAt.UTC().Format(time.RFC3339Nano),
		boolInt(g.OneTime), boolInt(g.HighRiskApproved), nullableString(g.BoundOperationID),
		g.KeyID, g.Signature, now)
	return err
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) GetGrant(ctx context.Context, id string) (bcp.Grant, error) {
	var g bcp.Grant
	var risksJSON, notBefore, expiresAt string
	var oneTime, highRisk int
	var bound sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id,subject,capability,target_prefix,risks_json,not_before,expires_at,one_time,high_risk_approved,bound_operation_id,key_id,signature FROM grants WHERE id=?`, id).
		Scan(&g.ID, &g.Subject, &g.Capability, &g.TargetPrefix, &risksJSON, &notBefore, &expiresAt, &oneTime, &highRisk, &bound, &g.KeyID, &g.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return bcp.Grant{}, ErrGrantNotFound
	}
	if err != nil {
		return bcp.Grant{}, err
	}
	if err := json.Unmarshal([]byte(risksJSON), &g.Risks); err != nil {
		return bcp.Grant{}, err
	}
	g.NotBefore, err = time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return bcp.Grant{}, err
	}
	g.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return bcp.Grant{}, err
	}
	g.OneTime = oneTime != 0
	g.HighRiskApproved = highRisk != 0
	if bound.Valid {
		g.BoundOperationID = bound.String
	}
	return g, nil
}

func (s *Store) ReserveGrant(ctx context.Context, id, operationID string) error {
	if operationID == "" {
		return errors.New("operation id is required")
	}
	var oneTime int
	var bound sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT one_time,bound_operation_id FROM grants WHERE id=?`, id).Scan(&oneTime, &bound)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrGrantNotFound
	}
	if err != nil {
		return err
	}
	if bound.Valid && bound.String != "" && bound.String != operationID {
		return errors.New("grant bound to another operation")
	}
	if oneTime == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`UPDATE grants SET consumed_by_operation_id=?,consumed_at=? WHERE id=? AND (consumed_by_operation_id IS NULL OR consumed_by_operation_id=?)`,
		operationID, now, id, operationID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var consumed sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT consumed_by_operation_id FROM grants WHERE id=?`, id).Scan(&consumed); err != nil {
		return err
	}
	if consumed.Valid && consumed.String == operationID {
		return nil
	}
	return ErrGrantConsumed
}

func (s *Store) EnqueueOutbox(ctx context.Context, item bcp.OutboxItem) (int64, error) {
	if item.MessageID == "" || item.Kind == "" {
		return 0, errors.New("message id and kind are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO outbox(message_id,operation_id,kind,body,created_at) VALUES(?,?,?,?,?)`,
		item.MessageID, nullableString(item.OperationID), item.Kind, item.Body, now)
	if err == nil {
		return res.LastInsertId()
	}
	var seq int64
	var opID sql.NullString
	var kind string
	var body []byte
	e := s.db.QueryRowContext(ctx, `SELECT seq,operation_id,kind,body FROM outbox WHERE message_id=?`, item.MessageID).
		Scan(&seq, &opID, &kind, &body)
	if e != nil {
		return 0, err
	}
	existingOp := ""
	if opID.Valid {
		existingOp = opID.String
	}
	if existingOp == item.OperationID && kind == item.Kind && bytes.Equal(body, item.Body) {
		return seq, nil
	}
	return 0, ErrOutboxConflict
}

func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]bcp.OutboxItem, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq,message_id,COALESCE(operation_id,''),kind,body,sent_count,state FROM outbox WHERE state='pending' ORDER BY seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bcp.OutboxItem
	for rows.Next() {
		var x bcp.OutboxItem
		if err := rows.Scan(&x.Seq, &x.MessageID, &x.OperationID, &x.Kind, &x.Body, &x.SentCount, &x.State); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) MarkSent(ctx context.Context, seq int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET sent_count=sent_count+1,last_sent_at=? WHERE seq=? AND state='pending'`,
		time.Now().UTC().Format(time.RFC3339Nano), seq)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return errors.New("pending outbox message not found")
	}
	return nil
}

func (s *Store) AckThrough(ctx context.Context, seq int64) error {
	if seq <= 0 {
		return errors.New("ack sequence must be positive")
	}
	var unsent int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM outbox WHERE seq<=? AND state='pending' AND sent_count=0`, seq).Scan(&unsent); err != nil {
		return err
	}
	if unsent != 0 {
		return ErrAckUnsent
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET state='acked',acked_at=? WHERE seq<=? AND state='pending' AND sent_count>0`,
		time.Now().UTC().Format(time.RFC3339Nano), seq)
	return err
}

func (s *Store) PutDevice(ctx context.Context, d bcp.DeviceEntry) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if d.CreatedAt == "" {
		d.CreatedAt = now
	}
	d.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO devices(id,generation,fingerprint,routing_eligible,publisher_deny,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				generation=excluded.generation,
				fingerprint=excluded.fingerprint,
				routing_eligible=excluded.routing_eligible,
				publisher_deny=excluded.publisher_deny,
				updated_at=excluded.updated_at`,
		d.ID, d.Generation, d.Fingerprint, boolInt(d.RoutingEligible), boolInt(d.PublisherDeny), d.CreatedAt, d.UpdatedAt)
	return err
}

func (s *Store) GetDevice(ctx context.Context, id string) (bcp.DeviceEntry, error) {
	var d bcp.DeviceEntry
	var re, pd int
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id,generation,fingerprint,routing_eligible,publisher_deny,created_at,updated_at FROM devices WHERE id=?`, id).
		Scan(&d.ID, &d.Generation, &d.Fingerprint, &re, &pd, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return bcp.DeviceEntry{}, ErrDeviceNotFound
	}
	if err != nil {
		return bcp.DeviceEntry{}, err
	}
	d.RoutingEligible = re != 0
	d.PublisherDeny = pd != 0
	d.CreatedAt = createdAt
	d.UpdatedAt = updatedAt
	return d, nil
}

func (s *Store) ListDevices(ctx context.Context) ([]bcp.DeviceEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,generation,fingerprint,routing_eligible,publisher_deny,created_at,updated_at FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bcp.DeviceEntry
	for rows.Next() {
		var d bcp.DeviceEntry
		var re, pd int
		var createdAt, updatedAt string
		if err := rows.Scan(&d.ID, &d.Generation, &d.Fingerprint, &re, &pd, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		d.RoutingEligible = re != 0
		d.PublisherDeny = pd != 0
		d.CreatedAt = createdAt
		d.UpdatedAt = updatedAt
		out = append(out, d)
	}
	return out, rows.Err()
}
