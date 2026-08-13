// Command fakegithub is a stand-in for GitHub used by the container
// integration harness in test/integration. It speaks just enough of the device
// authorization grant and the REST API for a real broker to complete a login,
// and it exposes a control API so the test driver can decide what GitHub does
// next.
//
// It is not a general-purpose mock and has no business outside the harness: it
// accepts any client credentials and any device code.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

// outcome is what the token endpoint will report for the next poll.
type outcome string

const (
	outcomePending outcome = "pending"
	outcomeGranted outcome = "granted"
	outcomeDenied  outcome = "denied"
	outcomeExpired outcome = "expired"
	userCode               = "WDJB-MJHT"
	deviceCode             = "fake-device-code"
	accessToken            = "gho_fakegithubfakegithubfakegithub12345678"
	defaultLogin           = "alice"
	defaultOrg             = "acme"
	defaultTeam            = "eng"
)

type state struct {
	mu      sync.Mutex
	outcome outcome
	login   string
	org     string
	// polls counts token-endpoint requests, so the driver can tell "the module
	// polled and was told to wait" from "the module never polled".
	polls int
	// revoked records tokens the broker asked GitHub to revoke.
	revoked []string
}

func (s *state) snapshot() (outcome, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outcome, s.login, s.org
}

func main() {
	apiAddr := flag.String("api-addr", ":8443", "HTTPS listen address for the GitHub API surface")
	controlAddr := flag.String("control-addr", ":8080", "HTTP listen address for the test control API")
	certFile := flag.String("cert", "/etc/fakegithub/cert.pem", "TLS certificate")
	keyFile := flag.String("key", "/etc/fakegithub/key.pem", "TLS private key")
	flag.Parse()

	s := &state{outcome: outcomePending, login: defaultLogin, org: defaultOrg}

	go func() {
		log.Printf("control API on %s", *controlAddr)
		if err := http.ListenAndServe(*controlAddr, s.controlMux()); err != nil {
			log.Fatalf("control listener: %v", err)
		}
	}()

	log.Printf("GitHub API on %s (TLS)", *apiAddr)
	if err := http.ListenAndServeTLS(*apiAddr, *certFile, *keyFile, s.githubMux()); err != nil {
		log.Fatalf("api listener: %v", err)
	}
}

// githubMux serves the endpoints the broker's GitHub provider talks to. The
// paths match a GitHub Enterprise Server installation, which is what the
// broker's github.base_url points at.
func (s *state) githubMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"device_code":               deviceCode,
			"user_code":                 userCode,
			"verification_uri":          "https://fakegithub/login/device",
			"verification_uri_complete": "https://fakegithub/login/device?user_code=" + userCode,
			"expires_in":                600,
			"interval":                  1,
		})
	})

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.polls++
		current := s.outcome
		n := s.polls
		s.mu.Unlock()

		log.Printf("poll %d -> %s", n, current)

		switch current {
		case outcomeGranted:
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"access_token": accessToken,
				"token_type":   "bearer",
				"scope":        "read:org,read:user,user:email",
			})
		case outcomeDenied:
			writeJSON(w, http.StatusOK, map[string]string{"error": "access_denied"})
		case outcomeExpired:
			writeJSON(w, http.StatusOK, map[string]string{"error": "expired_token"})
		default:
			writeJSON(w, http.StatusOK, map[string]string{"error": "authorization_pending"})
		}
	})

	// The identity endpoints live under /api/v3 on Enterprise Server.
	mux.HandleFunc("/api/v3/user", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(w, r) {
			return
		}
		_, login, _ := s.snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"login": login,
			"name":  strings.ToTitle(login[:1]) + login[1:],
			"email": login + "@example.com",
			"id":    1,
		})
	})

	mux.HandleFunc("/api/v3/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(w, r) {
			return
		}
		_, _, org := s.snapshot()
		writeJSON(w, http.StatusOK, []map[string]string{{"login": org}})
	})

	mux.HandleFunc("/api/v3/user/teams", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(w, r) {
			return
		}
		_, _, org := s.snapshot()
		writeJSON(w, http.StatusOK, []map[string]interface{}{
			{"slug": defaultTeam, "organization": map[string]string{"login": org}},
		})
	})

	// DELETE /api/v3/applications/{client_id}/token — token revocation.
	mux.HandleFunc("/api/v3/applications/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/token") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		s.mu.Lock()
		s.revoked = append(s.revoked, body.AccessToken)
		s.mu.Unlock()

		log.Printf("revoked a token")
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	return mux
}

// controlMux is the driver's handle on what GitHub does next. It is plain HTTP
// on a separate port so a test script needs nothing but curl.
func (s *state) controlMux() http.Handler {
	mux := http.NewServeMux()

	set := func(o outcome) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			s.outcome = o
			s.mu.Unlock()
			log.Printf("control: outcome = %s", o)
			_, _ = fmt.Fprintf(w, "%s\n", o)
		}
	}

	mux.HandleFunc("/control/authorize", set(outcomeGranted))
	mux.HandleFunc("/control/deny", set(outcomeDenied))
	mux.HandleFunc("/control/expire", set(outcomeExpired))

	// /control/login?login=X changes the identity GitHub reports, so the driver
	// can create a mapping that does not match the account being logged into.
	mux.HandleFunc("/control/login", func(w http.ResponseWriter, r *http.Request) {
		login := r.URL.Query().Get("login")
		if login == "" {
			http.Error(w, "login is required", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.login = login
		s.mu.Unlock()
		log.Printf("control: login = %s", login)
		_, _ = fmt.Fprintf(w, "%s\n", login)
	})

	mux.HandleFunc("/control/reset", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.outcome, s.login, s.org = outcomePending, defaultLogin, defaultOrg
		s.polls, s.revoked = 0, nil
		s.mu.Unlock()
		log.Printf("control: reset")
		_, _ = fmt.Fprintln(w, "reset")
	})

	mux.HandleFunc("/control/state", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"outcome": string(s.outcome),
			"login":   s.login,
			"org":     s.org,
			"polls":   s.polls,
			"revoked": len(s.revoked),
		})
	})

	return mux
}

// authorized enforces the bearer token, so a broker that fetched an identity
// without one would fail the harness rather than quietly pass it.
func (s *state) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+accessToken {
		log.Printf("rejecting %s: Authorization = %q", r.URL.Path, r.Header.Get("Authorization"))
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}
