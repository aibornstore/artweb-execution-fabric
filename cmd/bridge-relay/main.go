package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/identity"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/relay"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "certpin" {
		pin, err := transport.SPKISHA256FromPEMFile(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(pin)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "enqueue" {
		if err := enqueue(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "job" {
		if err := showJob(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func enqueue(commandPath string) error {
	raw, err := os.ReadFile(commandPath)
	if err != nil {
		return err
	}
	var cmd protocol.Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return err
	}

	agentID := strings.TrimSpace(os.Getenv("BRIDGE_AGENT_ID"))
	controllerKeyID := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_KEY_ID"))
	controllerPubPath := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_PUBLIC_KEY_FILE"))
	controllerKeyringPath := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_KEYRING_FILE"))
	grantKeyID := envOr("BRIDGE_GRANT_KEY_ID", controllerKeyID)
	grantPubPath := envOr("BRIDGE_GRANT_PUBLIC_KEY_FILE", controllerPubPath)
	grantKeyringPath := envOr("BRIDGE_GRANT_KEYRING_FILE", controllerKeyringPath)
	jobsPath := envOr("BRIDGE_RELAY_JOBS_DB", "data/jobs.db")
	if agentID == "" {
		return errors.New("enqueue requires BRIDGE_AGENT_ID")
	}

	controllerKeys, err := identity.LoadPublicKeySet(controllerKeyID, controllerPubPath, controllerKeyringPath)
	if err != nil {
		return fmt.Errorf("load controller public keys: %w", err)
	}
	grantKeys, err := identity.LoadPublicKeySet(grantKeyID, grantPubPath, grantKeyringPath)
	if err != nil {
		return fmt.Errorf("load grant public keys: %w", err)
	}
	jobs, err := relay.OpenJobStore(jobsPath)
	if err != nil {
		return err
	}
	defer jobs.Close()

	ingress := relay.Ingress{
		Jobs:            jobs,
		CommandVerifier: protocol.CommandVerifier{Keys: controllerKeys},
		GrantVerifier:   auth.Verifier{Keys: grantKeys},
		ExpectedAgentID: agentID,
	}
	job, duplicate, err := ingress.Enqueue(context.Background(), cmd)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "PASS", "command_id": job.Command.CommandID,
		"state": job.State, "duplicate": duplicate,
	})
}

func showJob(commandID string) error {
	commandID = strings.TrimSpace(commandID)
	if commandID == "" {
		return errors.New("command id is required")
	}
	jobsPath := envOr("BRIDGE_RELAY_JOBS_DB", "data/jobs.db")
	jobs, err := relay.OpenJobStore(jobsPath)
	if err != nil {
		return err
	}
	defer jobs.Close()
	job, err := jobs.Get(context.Background(), commandID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(job)
}

func run() error {
	listen := envOr("BRIDGE_RELAY_LISTEN", "127.0.0.1:8765")
	ledgerPath := envOr("BRIDGE_RELAY_LEDGER", "data/relay.jsonl")
	jobsPath := envOr("BRIDGE_RELAY_JOBS_DB", "data/jobs.db")
	agentID := strings.TrimSpace(os.Getenv("BRIDGE_AGENT_ID"))
	keyID := strings.TrimSpace(os.Getenv("BRIDGE_AGENT_KEY_ID"))
	pubPath := strings.TrimSpace(os.Getenv("BRIDGE_AGENT_PUBLIC_KEY_FILE"))
	certFile := strings.TrimSpace(os.Getenv("BRIDGE_RELAY_CERT_FILE"))
	tlsKeyFile := strings.TrimSpace(os.Getenv("BRIDGE_RELAY_TLS_KEY_FILE"))
	controllerListen := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_LISTEN"))
	controllerKeyID := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_KEY_ID"))
	controllerPubPath := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_PUBLIC_KEY_FILE"))
	controllerKeyringPath := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_KEYRING_FILE"))
	grantKeyID := envOr("BRIDGE_GRANT_KEY_ID", controllerKeyID)
	grantPubPath := envOr("BRIDGE_GRANT_PUBLIC_KEY_FILE", controllerPubPath)
	grantKeyringPath := envOr("BRIDGE_GRANT_KEYRING_FILE", controllerKeyringPath)
	if agentID == "" || keyID == "" || pubPath == "" {
		return errors.New("BRIDGE_AGENT_ID, BRIDGE_AGENT_KEY_ID and BRIDGE_AGENT_PUBLIC_KEY_FILE are required")
	}
	if (certFile == "") != (tlsKeyFile == "") {
		return errors.New("BRIDGE_RELAY_CERT_FILE and BRIDGE_RELAY_TLS_KEY_FILE must be provided together")
	}
	controllerConfigured := controllerKeyID != "" || controllerPubPath != "" || controllerKeyringPath != "" ||
		grantKeyID != "" || grantPubPath != "" || grantKeyringPath != ""
	if certFile == "" && !isLoopbackListen(listen) {
		return errors.New("plaintext relay may bind only to loopback; configure TLS for external bind")
	}
	if controllerListen != "" {
		if !controllerConfigured {
			return errors.New("BRIDGE_CONTROLLER_LISTEN requires controller ingress configuration")
		}
		if !isLoopbackListen(controllerListen) {
			return errors.New("BRIDGE_CONTROLLER_LISTEN must bind to loopback")
		}
	}

	pub, err := identity.ReadPublicFile(pubPath)
	if err != nil {
		return err
	}
	ledger, err := relay.OpenLedger(ledgerPath)
	if err != nil {
		return err
	}
	jobs, err := relay.OpenJobStore(jobsPath)
	if err != nil {
		return err
	}
	defer jobs.Close()

	var controllerHTTP *relay.ControllerHTTP
	if controllerConfigured {
		controllerKeys, err := identity.LoadPublicKeySet(controllerKeyID, controllerPubPath, controllerKeyringPath)
		if err != nil {
			return fmt.Errorf("load controller public keys: %w", err)
		}
		grantKeys, err := identity.LoadPublicKeySet(grantKeyID, grantPubPath, grantKeyringPath)
		if err != nil {
			return fmt.Errorf("load grant public keys: %w", err)
		}
		ingress := relay.Ingress{
			Jobs:            jobs,
			CommandVerifier: protocol.CommandVerifier{Keys: controllerKeys},
			GrantVerifier:   auth.Verifier{Keys: grantKeys},
			ExpectedAgentID: agentID,
		}
		controllerHTTP = &relay.ControllerHTTP{
			Ingress:         ingress,
			Jobs:            jobs,
			QueryVerifier:   protocol.JobQueryVerifier{Keys: controllerKeys},
			ExpectedAgentID: agentID,
		}
	}

	s := &relay.Server{
		Verifier: protocol.HelloVerifier{
			Keys: map[string]ed25519.PublicKey{keyID: pub},
		},
		Ledger:             ledger,
		Jobs:               jobs,
		ChallengeTTL:       30 * time.Second,
		JobLease:           30 * time.Second,
		JobPollInterval:    time.Second,
		ExpectedKeyByAgent: map[string]string{agentID: keyID},
	}
	includeControllerOnWorker := controllerHTTP != nil && controllerListen == ""
	workerMux := newWorkerMux(s, controllerHTTP, includeControllerOnWorker)
	workerServer := &http.Server{
		Addr: listen, Handler: workerMux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}

	var controllerServer *http.Server
	if controllerListen != "" {
		controllerServer = &http.Server{
			Addr:              controllerListen,
			Handler:           newControllerMux(controllerHTTP),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	return serveRelayServers(workerServer, certFile, tlsKeyFile, controllerServer)
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

func newWorkerMux(s *relay.Server, controllerHTTP *relay.ControllerHTTP, includeController bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/bridge", s)
	mux.HandleFunc("/worker", s.ServeWorkerHTTP)
	if includeController && controllerHTTP != nil {
		mux.HandleFunc("/controller/submit", controllerHTTP.Submit)
		mux.HandleFunc("/controller/query", controllerHTTP.Query)
	}
	mux.HandleFunc("/healthz", healthzHandler)
	return mux
}

func newControllerMux(controllerHTTP *relay.ControllerHTTP) *http.ServeMux {
	mux := http.NewServeMux()
	if controllerHTTP != nil {
		mux.HandleFunc("/controller/submit", controllerHTTP.Submit)
		mux.HandleFunc("/controller/query", controllerHTTP.Query)
	}
	mux.HandleFunc("/healthz", healthzHandler)
	return mux
}

func serveRelayServers(workerServer *http.Server, certFile, tlsKeyFile string, controllerServer *http.Server) error {
	serveWorker := func() error {
		if certFile != "" {
			fmt.Printf("bridge-relay worker listener on %s with TLS1.3+\n", workerServer.Addr)
			return workerServer.ListenAndServeTLS(certFile, tlsKeyFile)
		}
		fmt.Printf("bridge-relay worker listener on loopback %s without TLS termination\n", workerServer.Addr)
		return workerServer.ListenAndServe()
	}

	if controllerServer == nil {
		return serveWorker()
	}

	fmt.Printf("bridge-relay controller ingress on loopback %s without TLS termination\n", controllerServer.Addr)
	errCh := make(chan error, 2)
	go func() { errCh <- controllerServer.ListenAndServe() }()
	go func() { errCh <- serveWorker() }()

	err := <-errCh
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = controllerServer.Shutdown(ctx)
	_ = workerServer.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
