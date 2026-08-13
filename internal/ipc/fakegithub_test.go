package ipc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
)

// fakeGitHub is a stand-in for github.com covering every endpoint the provider
// touches: the device authorization and token endpoints, the three identity
// API calls, and token revocation.
//
// It exists so the end-to-end tests drive the real provider, broker, and IPC
// code rather than a mock of them. The device flow's defining property — that
// the token endpoint returns authorization_pending until the user acts
// out-of-band — is what makes the "pending is not authenticated" contract
// testable at all, so it is modelled explicitly via grantToken.
type fakeGitHub struct {
	srv *httptest.Server

	mu sync.Mutex
	// login, orgs, and teams are the identity /user, /user/orgs and
	// /user/teams report.
	login string
	orgs  []string
	teams []string
	// scope is the scope string the token endpoint claims to have granted.
	scope string
	// granted flips to true to simulate the user approving at GitHub. Until
	// then the token endpoint returns authorization_pending.
	granted bool
	// tokenError, if set, is returned by the token endpoint instead of a token
	// (e.g. "access_denied", "expired_token").
	tokenError string
	// accessToken is handed out once granted.
	accessToken string
	// pollCount counts token endpoint hits, so a test can assert the client
	// really polled rather than answering from a first-call fluke.
	pollCount int
	// revoked records the access tokens passed to the revocation endpoint.
	revoked []string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()

	f := &fakeGitHub{
		login:       "alice",
		orgs:        []string{"acme"},
		teams:       []string{"acme/eng"},
		scope:       "read:org,read:user,user:email",
		accessToken: "gho_faketoken_0123456789",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", f.handleDeviceCode)
	mux.HandleFunc("/login/oauth/access_token", f.handleToken)
	mux.HandleFunc("/user", f.handleUser)
	mux.HandleFunc("/user/orgs", f.handleOrgs)
	mux.HandleFunc("/user/teams", f.handleTeams)
	mux.HandleFunc("/applications/", f.handleRevoke)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fake github: unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// endpoints points a provider at this fake.
func (f *fakeGitHub) endpoints() github.Endpoints {
	return github.Endpoints{
		DeviceAuth: f.srv.URL + "/login/device/code",
		Token:      f.srv.URL + "/login/oauth/access_token",
		APIBase:    f.srv.URL,
	}
}

// grant simulates the user completing authorization in their browser.
func (f *fakeGitHub) grant() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.granted = true
}

// failWith makes the token endpoint return an RFC 8628 error code.
func (f *fakeGitHub) failWith(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenError = code
}

// setLogin changes the GitHub login the identity endpoints report.
func (f *fakeGitHub) setLogin(login string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.login = login
}

func (f *fakeGitHub) polls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pollCount
}

func (f *fakeGitHub) revokedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func (f *fakeGitHub) handleDeviceCode(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{
		"device_code":               "fake-device-code",
		"user_code":                 "WDJB-MJHT",
		"verification_uri":          "https://github.com/login/device",
		"verification_uri_complete": "https://github.com/login/device?user_code=WDJB-MJHT",
		// Short enough that a test can wait out an expiry, long enough that it
		// never expires mid-test by accident.
		"expires_in": 60,
		"interval":   1,
	})
}

func (f *fakeGitHub) handleToken(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollCount++

	switch {
	case f.tokenError != "":
		writeJSON(w, map[string]interface{}{"error": f.tokenError})
	case !f.granted:
		writeJSON(w, map[string]interface{}{"error": "authorization_pending"})
	default:
		writeJSON(w, map[string]interface{}{
			"access_token": f.accessToken,
			"token_type":   "bearer",
			"scope":        f.scope,
		})
	}
}

func (f *fakeGitHub) handleUser(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	login := f.login
	f.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"login": login,
		"name":  "Alice Example",
		"email": login + "@example.com",
		"id":    1234,
	})
}

func (f *fakeGitHub) handleOrgs(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	orgs := append([]string(nil), f.orgs...)
	f.mu.Unlock()

	out := make([]map[string]string, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, map[string]string{"login": o})
	}
	writeJSON(w, out)
}

func (f *fakeGitHub) handleTeams(w http.ResponseWriter, r *http.Request) {
	if !f.requireBearer(w, r) {
		return
	}
	f.mu.Lock()
	teams := append([]string(nil), f.teams...)
	f.mu.Unlock()

	out := make([]map[string]interface{}, 0, len(teams))
	for _, t := range teams {
		org, slug := splitTeam(t)
		out = append(out, map[string]interface{}{
			"slug":         slug,
			"organization": map[string]string{"login": org},
		})
	}
	writeJSON(w, out)
}

func (f *fakeGitHub) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// GitHub authenticates revocation with the client credentials, not a bearer.
	if _, _, ok := r.BasicAuth(); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.revoked = append(f.revoked, body.AccessToken)
	f.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// requireBearer rejects identity API calls that do not carry the access token,
// so a test cannot pass while the provider forgets to authenticate.
func (f *fakeGitHub) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	want := "Bearer " + f.accessToken
	f.mu.Unlock()
	if r.Header.Get("Authorization") != want {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func splitTeam(s string) (org, slug string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:]
		}
	}
	return "", s
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("fake github: encode response: %v", err))
	}
}
