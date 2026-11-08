package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type Config struct {
	Endpoint         string
	Header           http.Header
	ConnectTimeout   time.Duration
	ServerSPKISHA256 string
}

func ValidateEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "wss" {
		return nil, errors.New("only wss is allowed")
	}
	if u.Host == "" {
		return nil, errors.New("host required")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("credentials/query/fragment forbidden")
	}
	return u, nil
}

func ValidateExternalPinPolicy(raw, pin string) error {
	u, err := ValidateEndpoint(raw)
	if err != nil {
		return err
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	isLoopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if !isLoopback && strings.TrimSpace(pin) == "" {
		return errors.New("external WSS endpoint requires SPKI pin")
	}
	return nil
}

func tlsConfigForHost(host, pin string) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if pin == "" {
		return tlsCfg, nil
	}
	expected, err := hex.DecodeString(pin)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("invalid SPKI SHA256 pin")
	}
	tlsCfg.ServerName = host
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("peer certificate missing")
		}
		cert := cs.PeerCertificates[0]
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return errors.New("peer certificate outside validity window")
		}
		if err := cert.VerifyHostname(host); err != nil {
			return err
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], expected) != 1 {
			return errors.New("SPKI pin mismatch")
		}
		return nil
	}
	return tlsCfg, nil
}

func NewPinnedHTTPClient(raw, pin string, timeout time.Duration) (*http.Client, *url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if u.Host == "" {
		return nil, nil, errors.New("controller endpoint host is required")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, errors.New("credentials/query/fragment forbidden")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	isLoopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())

	tr := http.DefaultTransport.(*http.Transport).Clone()
	switch u.Scheme {
	case "http":
		if !isLoopback {
			return nil, nil, errors.New("plaintext controller endpoint is allowed only on loopback")
		}
		if strings.TrimSpace(pin) != "" {
			return nil, nil, errors.New("SPKI pin is invalid for plaintext loopback controller endpoint")
		}
	case "https":
		if !isLoopback && strings.TrimSpace(pin) == "" {
			return nil, nil, errors.New("external HTTPS endpoint requires SPKI pin")
		}
		tlsCfg, err := tlsConfigForHost(host, strings.TrimSpace(pin))
		if err != nil {
			return nil, nil, err
		}
		tr.TLSClientConfig = tlsCfg
	default:
		return nil, nil, errors.New("controller endpoint must use https, or http on loopback")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{Transport: tr, Timeout: timeout}, u, nil
}

func Dial(ctx context.Context, cfg Config) (*websocket.Conn, *http.Response, error) {
	if err := ValidateExternalPinPolicy(cfg.Endpoint, cfg.ServerSPKISHA256); err != nil {
		return nil, nil, err
	}
	u, err := ValidateEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	t := cfg.ConnectTimeout
	if t <= 0 {
		t = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg, err := tlsConfigForHost(u.Hostname(), strings.TrimSpace(cfg.ServerSPKISHA256))
	if err != nil {
		return nil, nil, err
	}
	tr.TLSClientConfig = tlsCfg
	hc := &http.Client{Transport: tr}
	return websocket.Dial(ctx, cfg.Endpoint, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: cfg.Header})
}
