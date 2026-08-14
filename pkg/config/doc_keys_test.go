package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every config key the documentation names has to exist — #107.
//
// README.md gave tier 0's config key as `mapper.enrollment_file`, and the key that
// switches tier 0 on is `mapper.enrollment_enabled`. Following the README produced a
// broker that refused to start ("at least one tier must be configured"), and adding
// a rule to get past that produced one where tier 0 was never consulted, so every
// enrolled user was silently ignored while oauth2-pam-enroll appeared to work.
//
// The structural gap is why it lasted: config_test.go loads and validates the
// shipped configs/example.yaml, so the example is protected by a test and the prose
// is not. This closes that by taking the documentation's word for it — every dotted
// key in backticks under a known top-level section has to resolve to a real
// mapstructure tag.
//
// It does not check that a key means what the prose says it means. Nothing
// mechanical can. It checks the one thing that keeps being wrong: whether the key is
// there at all.
func TestEveryConfigKeyNamedInTheDocsExists(t *testing.T) {
	valid := configKeys(reflect.TypeOf(Config{}), "")
	sections := map[string]bool{}
	for k := range valid {
		sections[strings.Split(k, ".")[0]] = true
	}

	for _, file := range docFiles(t) {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, key := range dottedKeysIn(string(body), sections) {
			if _, ok := valid[key]; !ok {
				t.Errorf("%s names config key %q, which does not exist. Candidates: %s",
					filepath.Base(file), key, strings.Join(nearestKeys(key, valid), ", "))
			}
		}
	}
}

// docFiles is every prose file an operator is expected to configure from. Named
// explicitly rather than globbed from the repository root, so that a new document
// is added here deliberately and a stray file elsewhere does not fail the suite.
func docFiles(t *testing.T) []string {
	t.Helper()
	// This test runs in pkg/config, so the repository root is two levels up.
	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "SECURITY.md"),
	}
	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatalf("glob docs: %v", err)
	}
	files = append(files, docs...)
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("stat %s: %v — this test's file list has gone stale", f, err)
		}
	}
	return files
}

// docKeyRe matches a dotted lower-case token, with optional [] or [0] index
// segments: mapper.min_uid, providers[].name, audit.outputs[].path.
var docKeyRe = regexp.MustCompile(`^[a-z0-9_]+(\[\]|\[[0-9]+\])?(\.[a-z0-9_]+(\[\]|\[[0-9]+\])?)+$`)

// indexRe strips the index segments, since a slice's element fields live under the
// slice's own key.
var indexRe = regexp.MustCompile(`\[[0-9]*\]`)

// dottedKeysIn returns the config keys named in backticks in body.
//
// Backticks are the filter that makes this safe to run over prose: an unquoted
// "audit outputs" is not a claim about a key. The section filter is the second — it
// is what keeps `github.com`, `api.github.com` and every other dotted thing in a
// document about OAuth2 from being read as configuration.
func dottedKeysIn(body string, sections map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, span := range strings.Split(body, "`")[1:] {
		token := strings.TrimSpace(span)
		if !docKeyRe.MatchString(token) {
			continue
		}
		key := indexRe.ReplaceAllString(token, "")
		if !sections[strings.Split(key, ".")[0]] || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// configKeys returns every dotted mapstructure path in t.
//
// A slice of structs contributes its own key and its element's fields beneath it, so
// providers[].name and audit.outputs[].path resolve. A map stops the walk: its keys
// are data, not configuration — mapper.rules[].claims is a set of provider claim
// names, and no list of them could be checked here.
func configKeys(t reflect.Type, prefix string) map[string]struct{} {
	keys := map[string]struct{}{}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return keys
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("mapstructure"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		keys[key] = struct{}{}

		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			for k := range configKeys(ft, key) {
				keys[k] = struct{}{}
			}
		}
	}
	return keys
}

// nearestKeys returns the real keys sharing the bad key's section, so a failure says
// what the writer probably meant rather than only that they were wrong.
func nearestKeys(bad string, valid map[string]struct{}) []string {
	section := strings.Split(bad, ".")[0] + "."
	var out []string
	for k := range valid {
		if strings.HasPrefix(k, section) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestTheDocKeyScanFindsTheKeysTheDocsActuallyName is the control. The test above
// passes trivially if the scan finds nothing — a broken regexp, a changed section
// name, a file list gone stale — and "no keys named in the docs" is exactly what a
// silently-broken scan looks like.
func TestTheDocKeyScanFindsTheKeysTheDocsActuallyName(t *testing.T) {
	valid := configKeys(reflect.TypeOf(Config{}), "")
	sections := map[string]bool{}
	for k := range valid {
		sections[strings.Split(k, ".")[0]] = true
	}

	found := map[string]bool{}
	for _, file := range docFiles(t) {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, k := range dottedKeysIn(string(body), sections) {
			found[k] = true
		}
	}

	// The tier-0 key #107 was about, plus one from each of the other files that name
	// any, so a scan that stopped reading one of them fails here.
	for _, want := range []string{
		"mapper.enrollment_enabled",
		"mapper.min_uid",
		"providers.name",
		"server.read_timeout",
	} {
		if !found[want] {
			t.Errorf("the scan did not find %q in the documentation, so it is not reading what it "+
				"is meant to be checking", want)
		}
	}
	if len(found) < 8 {
		t.Errorf("the scan found only %d config keys across the documentation (%v); it found 13 when "+
			"it was written, so it has probably stopped matching", len(found), found)
	}
}
