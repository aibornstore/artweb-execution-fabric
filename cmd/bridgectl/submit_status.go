package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/identity"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

type controllerHTTPError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *controllerHTTPError) Error() string {
	return fmt.Sprintf("relay %s: %s", e.Status, e.Body)
}

func controllerHTTPStatus(err error, status int) bool {
	var httpErr *controllerHTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == status
}

func permanentControllerError(err error) bool {
	var httpErr *controllerHTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 &&
		httpErr.StatusCode != http.StatusRequestTimeout &&
		httpErr.StatusCode != http.StatusTooManyRequests
}

func submitStatus(agentID, relayBase string) error {
	agentID = strings.TrimSpace(agentID)
	relayBase = strings.TrimSpace(relayBase)
	if agentID == "" || relayBase == "" {
		return errors.New("agent id and relay base URL are required")
	}
	keyID := envOr("BRIDGE_CONTROLLER_KEY_ID", "controller-main")
	dir := envOr("BRIDGE_CONTROLLER_IDENTITY_DIR", ".controller")
	actorID := envOr("BRIDGE_ACTOR_ID", "owner")
	pair, err := identity.Load(dir, keyID)
	if err != nil {
		return err
	}
	cmd, err := buildStatusCommand(agentID, actorID, keyID, pair.Private)
	if err != nil {
		return err
	}
	return submitSignedCommand(agentID, relayBase, keyID, pair.Private, cmd)
}

func buildStatusCommand(agentID, actorID, keyID string, privateKey ed25519.PrivateKey) (protocol.Command, error) {
	id, err := randomID(16)
	if err != nil {
		return protocol.Command{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(2 * time.Minute)
	grant := bcp.Grant{
		ID: "grant-" + id, Subject: actorID, Capability: limitedexec.HostStatusCapability,
		TargetPrefix: "device://" + agentID + "/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-15 * time.Second), ExpiresAt: expires,
	}
	grant, err = auth.SignGrant(grant, keyID, privateKey)
	if err != nil {
		return protocol.Command{}, err
	}
	nonce, err := protocol.NewCommandNonce()
	if err != nil {
		return protocol.Command{}, err
	}
	cmd := protocol.Command{
		CommandID: id, AgentID: agentID,
		Operation: bcp.Operation{
			ID: id, IdempotencyKey: "host-status-" + id, ActorID: actorID,
			Capability: limitedexec.HostStatusCapability,
			Target:     "device://" + agentID + "/status",
			Action:     "read", Risk: bcp.RiskRead,
		},
		Grant: grant, IssuedAt: now, ExpiresAt: expires, Nonce: nonce,
	}
	return protocol.SignCommand(cmd, keyID, privateKey)
}

func submitSignedCommand(agentID, relayBase, keyID string, privateKey ed25519.PrivateKey, cmd protocol.Command) error {
	pin := strings.TrimSpace(os.Getenv("BRIDGE_TLS_SPKI_SHA256"))
	client, base, err := transport.NewPinnedHTTPClient(relayBase, pin, 15*time.Second)
	if err != nil {
		return err
	}
	timeout, err := controllerWaitTimeout()
	if err != nil {
		return err
	}
	return submitSignedCommandWithClient(agentID, keyID, privateKey, cmd, client, base, timeout)
}

func controllerWaitTimeout() (time.Duration, error) {
	timeout := 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return 0, errors.New("invalid BRIDGE_CONTROLLER_TIMEOUT")
		}
		timeout = parsed
	}
	return timeout, nil
}

func submitSignedCommandWithClient(agentID, keyID string, privateKey ed25519.PrivateKey, cmd protocol.Command, client *http.Client, base *url.URL, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	submit := func(ctx context.Context) (protocol.Job, error) {
		var submitted struct {
			Status    string       `json:"status"`
			Duplicate bool         `json:"duplicate"`
			Job       protocol.Job `json:"job"`
		}
		err := postControllerJSON(ctx, client, endpointURL(base, "/controller/submit"), cmd, &submitted)
		if err != nil {
			return protocol.Job{}, err
		}
		if submitted.Status != "PASS" || submitted.Job.Command.CommandID != cmd.CommandID {
			return protocol.Job{}, errors.New("relay returned inconsistent submit response")
		}
		return submitted.Job, nil
	}

	job, submitErr := submit(context.Background())
	if submitErr == nil {
		if job.State == "completed" {
			return printCompletedJob(job)
		}
	} else if permanentControllerError(submitErr) {
		return submitErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// A short http.Client.Timeout is useful for detecting an ambiguous submit,
	// but recovery queries must be governed by the overall controller deadline.
	// Reusing the same short Client.Timeout here can make an already-accepted
	// command look lost and incorrectly trigger a timeout/fallback.
	queryClient := *client
	queryClient.Timeout = 0
	var lastErr error = submitErr
	retrySubmit := submitErr != nil

	for {
		queried, found, err := queryControllerJob(ctx, &queryClient, base, agentID, keyID, privateKey, cmd.CommandID)
		if err == nil && found {
			if queried.Command.CommandID != cmd.CommandID || queried.Command.AgentID != agentID {
				return errors.New("relay returned inconsistent job identity")
			}
			retrySubmit = false
			lastErr = nil
			if queried.State == "completed" {
				return printCompletedJob(queried)
			}
		} else if err != nil {
			lastErr = err
			if permanentControllerError(err) {
				return err
			}
		}

		if retrySubmit {
			retried, err := submit(ctx)
			if err == nil {
				retrySubmit = false
				lastErr = nil
				if retried.State == "completed" {
					return printCompletedJob(retried)
				}
			} else {
				lastErr = err
				if permanentControllerError(err) {
					return err
				}
			}
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("controller wait timeout for command %s after ambiguous submit: %v: %w", cmd.CommandID, lastErr, ctx.Err())
			}
			return fmt.Errorf("controller wait timeout for command %s: %w", cmd.CommandID, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func queryControllerJob(ctx context.Context, client *http.Client, base *url.URL, agentID, keyID string, privateKey ed25519.PrivateKey, commandID string) (protocol.Job, bool, error) {
	now := time.Now().UTC()
	q, err := protocol.SignJobQuery(protocol.JobQuery{
		CommandID: commandID,
		AgentID:   agentID,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Minute),
	}, keyID, privateKey)
	if err != nil {
		return protocol.Job{}, false, err
	}
	var job protocol.Job
	err = postControllerJSON(ctx, client, endpointURL(base, "/controller/query"), q, &job)
	if controllerHTTPStatus(err, http.StatusNotFound) {
		return protocol.Job{}, false, nil
	}
	if err != nil {
		return protocol.Job{}, false, err
	}
	return job, true, nil
}

func endpointURL(base *url.URL, path string) string {
	u := *base
	u.Path = path
	u.RawPath = ""
	return u.String()
}

func postControllerJSON(ctx context.Context, client *http.Client, endpoint string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &controllerHTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}
	return nil
}

func printCompletedJob(job protocol.Job) error {
	if job.Result == nil {
		return errors.New("completed job missing result")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":     "PASS",
		"state":      job.State,
		"command_id": job.Command.CommandID,
		"command":    job.Command,
		"result":     job.Result,
	})
}
