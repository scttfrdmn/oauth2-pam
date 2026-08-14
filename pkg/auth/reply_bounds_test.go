package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The bounds on an authorized reply — #88.
//
// Until they existed the only limit on an authorized reply was the socket's 16 KiB
// cap in internal/ipc, and that cap substitutes RESPONSE_TOO_LARGE, which the
// module maps to a terminal PAM_AUTHINFO_UNAVAIL. The session behind the oversized
// reply stayed authorized and active, counted toward max_concurrent_sessions and
// held a live token for token_lifetime — so ten attempts locked the user out for
// eight hours behind ten authorized sessions no client could resolve. Three fields
// could get there and none of them are ours: email and provider_login come from the
// provider, and Groups arrives through a mapper tier whose own limit is 1 MB.
//
// These are the field-level bounds. internal/ipc's authorized-reply test measures
// the result against the cap itself.

func TestBoundedReplyFieldStripsControlCharacters(t *testing.T) {
	// A NUL, a newline, an ESC introducing a terminal sequence, and a DEL.
	got := boundedReplyField("al\x00ice\n\x1b[2Jbob\x7f", maxReplyEmailBytes)

	for i, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Errorf("byte %d of %q is control character %#x", i, got, r)
		}
	}
	if !utf8.ValidString(got) {
		t.Errorf("%q is not valid UTF-8", got)
	}
	if strings.ContainsAny(got, "\x00\n\x1b\x7f") {
		t.Errorf("%q still carries a control character", got)
	}
	// The printable remainder survives: stripping is not sanitizing away the value.
	if !strings.Contains(got, "alice") || !strings.Contains(got, "bob") {
		t.Errorf("%q dropped printable content", got)
	}
}

func TestBoundedReplyFieldTruncatesOnARuneBoundary(t *testing.T) {
	// Two-byte runes against an odd budget, so a byte-wise truncation would split
	// the last one and put an invalid encoding on the wire.
	got := boundedReplyField(strings.Repeat("é", 100), 5)

	if len(got) > 5 {
		t.Errorf("len(%q) = %d, want at most 5", got, len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("%q is not valid UTF-8; a rune was split", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Errorf("%q contains U+FFFD", got)
	}
	if got != "éé" {
		t.Errorf("got %q, want %q — two runes fit in five bytes and a third does not", got, "éé")
	}
}

func TestBoundedReplyFieldLeavesOrdinaryValuesAlone(t *testing.T) {
	for _, s := range []string{"", "alice", "alice@example.com", "Ünïcödé Name"} {
		if got := boundedReplyField(s, maxReplyEmailBytes); got != s {
			t.Errorf("boundedReplyField(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestReplyGroupsKeepsARealisticMembership(t *testing.T) {
	groups := []string{"devs", "research-computing", "hpc-users", "wheel"}

	got, omitted := replyGroups(groups)
	if omitted {
		t.Error("a four-group membership was dropped; the bound is meant to stop pathological lists, not real ones")
	}
	if len(got) != len(groups) {
		t.Errorf("got %d groups, want %d", len(got), len(groups))
	}
}

// TestReplyGroupsDropsALongListWholeRatherThanTruncating: a truncated list is
// indistinguishable from a complete one, so a client acting on group membership
// would act on a list missing whichever entries happened to sort last. Omission is
// at least honest, and successResponse says so in metadata.
func TestReplyGroupsDropsALongListWholeRatherThanTruncating(t *testing.T) {
	cases := map[string][]string{
		"more groups than the count allows": makeGroups(maxReplyGroups+1, 8),
		// The mapper's own comment used to endorse this size: "a user in a thousand
		// groups is a few tens of KB, so 1 MB is generous".
		"the thousand-group user the mapper comment endorsed": makeGroups(1000, 20),
		// Inside the count, over the byte total. Both bounds have to be able to fire.
		"few enough groups, too many bytes": makeGroups(maxReplyGroups, maxReplyGroupBytes),
	}

	for name, groups := range cases {
		t.Run(name, func(t *testing.T) {
			got, omitted := replyGroups(groups)
			if !omitted {
				t.Errorf("a %d-group list was accepted", len(groups))
			}
			if got != nil {
				t.Errorf("got %d groups, want none: a partial list reads as a complete one", len(got))
			}
		})
	}
}

func TestReplyGroupsBoundsEachName(t *testing.T) {
	// One over-long name in an otherwise small list: the list stays, the name is cut.
	got, omitted := replyGroups([]string{"devs", strings.Repeat("g", 4096)})
	if omitted {
		t.Fatal("a two-group list was dropped because one name was long")
	}
	if len(got) != 2 {
		t.Fatalf("got %d groups, want 2", len(got))
	}
	if len(got[1]) > maxReplyGroupBytes {
		t.Errorf("group name is %d bytes, want at most %d", len(got[1]), maxReplyGroupBytes)
	}
}

// TestAnAuthorizedReplyIsBoundedWhateverTheSessionCarries is the field-level
// statement of the fix: every value in the reply that somebody else chose the
// length of comes out bounded, whatever arrived on the session.
func TestAnAuthorizedReplyIsBoundedWhateverTheSessionCarries(t *testing.T) {
	// successResponse reads no broker state; the receiver is there for consistency
	// with its siblings.
	b := &Broker{}

	session := &Session{
		ID:        strings.Repeat("ab", 16),
		LocalUser: "alice", // already through unixUsernameRe by this point
		// A hostile or misconfigured GHES named by api_base_url can answer with
		// anything; the response-body cap is 1 MB.
		Email:         strings.Repeat("a", 20000) + "@example.com",
		ProviderLogin: strings.Repeat("l", 20000),
		Groups:        makeGroups(700, 20),
		Provider:      "acme",
		ExpiresAt:     time.Now().Add(8 * time.Hour),
		LastAccessed:  time.Now(),
	}

	resp := b.successResponse(session)

	if !resp.Success || resp.Status != StatusAuthorized {
		t.Fatalf("status = %q success = %v; the reply still has to authorize the login",
			resp.Status, resp.Success)
	}
	if resp.UserID != "alice" {
		t.Errorf("user_id = %q, want alice", resp.UserID)
	}
	if len(resp.Email) > maxReplyEmailBytes {
		t.Errorf("email is %d bytes, want at most %d", len(resp.Email), maxReplyEmailBytes)
	}
	if got := len(resp.Metadata["provider_login"]); got > maxReplyProviderLoginBytes {
		t.Errorf("provider_login is %d bytes, want at most %d", got, maxReplyProviderLoginBytes)
	}
	if len(resp.Groups) != 0 {
		t.Errorf("got %d groups, want none for a 700-group session", len(resp.Groups))
	}
	// An omitted list has to be distinguishable from an empty one: a client that
	// grows a use for groups (#39) would otherwise read "no groups" and act on it.
	if resp.Metadata["groups_omitted"] != "true" {
		t.Error("metadata.groups_omitted is not set, so the dropped list is indistinguishable from no membership")
	}

	// The whole reply, measured the way it travels. internal/ipc's cap is 16 KiB and
	// this is the pkg/auth-side statement that a reply cannot approach it; the
	// end-to-end measurement against the constant itself lives beside that cap.
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	if len(encoded) > 8192 {
		t.Errorf("an authorized reply for a pathological session is %d bytes; "+
			"the socket cap is 16384 and a bound that close to it is not a bound", len(encoded))
	}
}

// TestAnOmittedGroupListIsNotClaimedWhenGroupsFit is the control: the metadata flag
// must mean something. If it were always set, the assertion above would pass for a
// broker that had stopped sending groups altogether.
func TestAnOmittedGroupListIsNotClaimedWhenGroupsFit(t *testing.T) {
	b := &Broker{}
	resp := b.successResponse(&Session{
		ID:        "session",
		LocalUser: "alice",
		Groups:    []string{"devs", "wheel"},
	})

	if _, ok := resp.Metadata["groups_omitted"]; ok {
		t.Error("groups_omitted is set on a reply that carries its groups")
	}
	if len(resp.Groups) != 2 {
		t.Errorf("got %d groups, want 2", len(resp.Groups))
	}
}

// makeGroups builds n distinct group names, each padded to width bytes (or left
// longer, if the serial number alone is wider than that).
func makeGroups(n, width int) []string {
	groups := make([]string, n)
	for i := range groups {
		name := fmt.Sprintf("group-%06d", i)
		if len(name) < width {
			name += strings.Repeat("x", width-len(name))
		}
		groups[i] = name
	}
	return groups
}
