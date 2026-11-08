package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aibornstore/artweb-execution-fabric/internal/relay"
)

func TestIsLoopbackListen(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8765", "localhost:8765", "[::1]:8765"} {
		if !isLoopbackListen(addr) {
			t.Fatalf("expected loopback: %s", addr)
		}
	}
	for _, addr := range []string{":8765", "0.0.0.0:8765", "192.0.2.1:8765", "bad"} {
		if isLoopbackListen(addr) {
			t.Fatalf("must not classify as loopback: %s", addr)
		}
	}
}

func TestSplitControllerRouting(t *testing.T) {
	s := &relay.Server{}
	controller := &relay.ControllerHTTP{}

	external := newWorkerMux(s, controller, false)
	req := httptest.NewRequest(http.MethodGet, "/controller/submit", nil)
	res := httptest.NewRecorder()
	external.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("split external listener exposed controller route: status=%d", res.Code)
	}

	local := newControllerMux(controller)
	req = httptest.NewRequest(http.MethodGet, "/controller/submit", nil)
	res = httptest.NewRecorder()
	local.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("loopback controller listener missing route: status=%d", res.Code)
	}

	legacy := newWorkerMux(s, controller, true)
	req = httptest.NewRequest(http.MethodGet, "/controller/submit", nil)
	res = httptest.NewRecorder()
	legacy.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("legacy single-listener controller route regressed: status=%d", res.Code)
	}
}

func TestSplitMuxHealthz(t *testing.T) {
	s := &relay.Server{}
	for name, mux := range map[string]http.Handler{
		"worker":     newWorkerMux(s, nil, false),
		"controller": newControllerMux(nil),
	} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s healthz status=%d", name, res.Code)
		}
		if res.Body.String() != "ok\n" {
			t.Fatalf("%s healthz body=%q", name, res.Body.String())
		}
	}
}
