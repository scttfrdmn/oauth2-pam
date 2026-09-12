package security

import (
	"encoding/json"
	"fmt"
	"sort"
)

// How large an audit record is allowed to be, and why the answer is not "as large
// as the truth" — #104.
//
// An AuditEvent carries strings the broker did not choose: an email and a login
// from the identity provider, a group list from the mapper, and a claims map that
// is whatever the provider's user endpoint returned. None of those had a byte
// bound anywhere. pkg/provider/github's apiGetAll bounds pages (20) and entries
// (2000) and never the accumulated size; provider.AddClaim bounds nothing.
//
// That would be a memory question and not much else if the record were written on
// a background goroutine. It is not: an event recording an access decision is
// marshalled and fsynced on the login's own goroutine, and a write that fails
// refuses the login. So an oversized record is not merely a large log line, it is
// a slow login, and — once the volume it is written to fills — a host that refuses
// every login after it. The fail-closed guarantee is what turns a disk-space
// problem into an outage, which is the reason to bound the input rather than to
// widen the disk.
//
// Measured before this existed: 2000 claim entries of 10 KiB produced a single
// 20,495,142-byte record, marshalled in 25 ms and written synchronously in 17 ms.
//
// The reply path already bounds these same three values — boundedReplyField for
// the email and the provider login, replyGroups for the groups — and pkg/mapper's
// comment on accepting a 1 MB answer says the extra "is used for the decision and
// then left out of the reply". It was not left out of the record. The bound lives
// here, at the one point every producer of every event passes through, rather than
// at the call site that happened to be found: #102 and #104 are both a mitigation
// that was correct and had a caller who did not use it, and a per-call-site fix
// invites the third one.
const (
	// maxAuditStringBytes bounds each single-line string field. Deliberately larger
	// than any equivalent ceiling on the reply (the widest is the 512-byte error
	// message), so that nothing a client is told is missing from the trail — a record
	// less complete than the message it describes would be the worse failure.
	maxAuditStringBytes = 1024

	// maxAuditGroupBytes and maxAuditGroups bound the mapper's group list: 128
	// entries of 256 bytes, so 32 KiB in the worst case. A Unix group name cannot
	// approach 256 bytes and a user cannot be in 128 groups that matter, but both are
	// well clear of any real answer.
	maxAuditGroupBytes = 256
	maxAuditGroups     = 128

	// maxAuditMetadataKeys and maxAuditMetadataValueBytes bound Metadata, which is
	// map[string]interface{} and therefore the only field whose size no type bounds.
	// The value budget is measured on the marshalled form, because that is the thing
	// being written and a nested map's size is not visible any other way.
	maxAuditMetadataKeys       = 32
	maxAuditMetadataValueBytes = 4096

	// maxAuditRecordBytes is the backstop, applied to the marshalled record after
	// every field bound above. It exists because the per-field bounds are a sum, and
	// a sum is an argument rather than a limit: this is the limit.
	maxAuditRecordBytes = 64 * 1024
)

// auditTruncationKey is the metadata key under which a record says what it lost.
//
// A truncated record that does not say so is worse than either a complete one or a
// refused one, because it reads as complete: an investigator counting a user's
// groups would count the ones that fit. Every path below that drops or shortens
// anything records it here, and the key is reserved — a producer's own value under
// this name is replaced rather than merged, so nothing can forge "nothing was
// truncated".
const auditTruncationKey = "audit_truncated"

// boundEvent returns event with every field it does not control bounded, and a
// note under auditTruncationKey saying what that cost.
//
// Applied in LogAuthEventErr before the critical/queued split, so an oversized
// event never reaches the channel either — queueing 20 MB to be dropped later is
// still 20 MB held.
func boundEvent(event AuditEvent) AuditEvent {
	var lost []string

	// The fields that arrive over IPC (user_id, source_ip, target_host, session_id)
	// are bounded by internal/ipc's requestFields before they get here, and the ones
	// this package sets (event_type, event_id) are literals. They are bounded anyway:
	// the point of a chokepoint is not to depend on what reached it.
	event.EventType = boundAuditString(event.EventType, "event_type", &lost)
	event.EventID = boundAuditString(event.EventID, "event_id", &lost)
	event.UserID = boundAuditString(event.UserID, "user_id", &lost)
	event.Email = boundAuditString(event.Email, "email", &lost)
	event.SourceIP = boundAuditString(event.SourceIP, "source_ip", &lost)
	event.TargetHost = boundAuditString(event.TargetHost, "target_host", &lost)
	event.SessionID = boundAuditString(event.SessionID, "session_id", &lost)
	event.Provider = boundAuditString(event.Provider, "provider", &lost)
	event.AuthMethod = boundAuditString(event.AuthMethod, "auth_method", &lost)
	event.ErrorMessage = boundAuditString(event.ErrorMessage, "error_message", &lost)
	event.ErrorCode = boundAuditString(event.ErrorCode, "error_code", &lost)

	event.Groups = boundAuditGroups(event.Groups, &lost)
	event.Metadata = boundAuditMetadata(event.Metadata, &lost)

	if len(lost) == 0 {
		return event
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{}, 1)
	}
	sort.Strings(lost)
	event.Metadata[auditTruncationKey] = lost

	// The note itself can push a record that just fitted over the backstop, so the
	// backstop is checked after it is added, not before.
	return backstopEvent(event)
}

// boundAuditString truncates s to maxAuditStringBytes on a rune boundary and
// appends field to lost if anything went.
//
// Truncating rather than dropping, because a shortened email or error message
// still identifies the login it belongs to, and identifying the login is most of
// what the field is for.
func boundAuditString(s, field string, lost *[]string) string {
	if len(s) <= maxAuditStringBytes {
		return s
	}
	*lost = append(*lost, field)
	return truncateAtRuneBoundary(s, maxAuditStringBytes)
}

// truncateAtRuneBoundary cuts s to at most max bytes without splitting a rune. A
// split rune would make the record invalid UTF-8, which json.Marshal answers by
// substituting U+FFFD — a silent edit to a field that is being recorded precisely
// so it can be read back verbatim.
func truncateAtRuneBoundary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && !utf8Start(s[end]) {
		end--
	}
	return s[:end]
}

// utf8Start reports whether b begins a UTF-8 sequence, i.e. is not a continuation
// byte (0b10xxxxxx).
func utf8Start(b byte) bool { return b&0xc0 != 0x80 }

// boundAuditGroups omits the group list entirely when it does not fit, rather than
// truncating it.
//
// This is the reply's rule, for the reply's reason, which docs/wire-protocol.md
// states as "a truncated list is indistinguishable from a complete one, and a
// client acting on membership would act on a list missing whichever entries sorted
// last. Omission is at least honest." An investigator reading the trail is that
// client. The count is kept, because "this user was in 4000 groups" is the useful
// half of an answer that does not fit.
func boundAuditGroups(groups []string, lost *[]string) []string {
	if len(groups) == 0 {
		return groups
	}

	total := 0
	oversize := false
	for _, g := range groups {
		if len(g) > maxAuditGroupBytes {
			oversize = true
		}
		total += len(g)
	}
	if len(groups) <= maxAuditGroups && !oversize && total <= maxAuditGroups*maxAuditGroupBytes {
		return groups
	}

	*lost = append(*lost, fmt.Sprintf("groups (%d entries omitted)", len(groups)))
	return nil
}

// boundAuditMetadata bounds the one field whose type bounds nothing.
//
// Each value is measured on its marshalled form, which is the only way to see the
// size of a nested map — identity.Claims arrives here as map[string]interface{} of
// unknown depth. A value that does not fit is replaced by a note giving its size
// rather than dropped, so the trail says a claim set was present and how big it
// was; a value that will not marshal at all is replaced too, rather than being
// left to fail the whole record.
func boundAuditMetadata(md map[string]interface{}, lost *[]string) map[string]interface{} {
	if len(md) == 0 {
		return md
	}

	keys := make([]string, 0, len(md))
	for k := range md {
		// Reserved: a producer does not get to write the field that says what was
		// truncated, or "nothing was" becomes forgeable.
		if k == auditTruncationKey {
			*lost = append(*lost, "metadata."+auditTruncationKey+" (reserved key discarded)")
			continue
		}
		keys = append(keys, k)
	}
	// Sorted so that which keys survive a key-count overflow is deterministic, and
	// so two records of the same shape lose the same fields.
	sort.Strings(keys)

	out := make(map[string]interface{}, len(keys))
	for i, k := range keys {
		if i >= maxAuditMetadataKeys {
			*lost = append(*lost, fmt.Sprintf("metadata (%d of %d keys omitted)",
				len(keys)-maxAuditMetadataKeys, len(keys)))
			break
		}
		bk := boundAuditString(k, "metadata key "+k, lost)
		encoded, err := json.Marshal(md[k])
		switch {
		case err != nil:
			// Left exactly as it arrived, which means writeEvent's json.Marshal fails and
			// LogAuthEventErr returns an error reporting the record as never written.
			//
			// Substituting a note here instead would be a kindness with a cost: it would
			// make an unmarshallable event succeed, and the contract that says so — a
			// marshal failure is the one failure where no sink can hold the record, so
			// RecordMayHaveLanded is false and the caller must not write a correction
			// (#94) — would have no reachable path left to test. This function bounds
			// size; it does not decide what a broken producer's event means.
			out[bk] = md[k]
		case len(encoded) > maxAuditMetadataValueBytes:
			*lost = append(*lost, fmt.Sprintf("metadata.%s (%d bytes omitted)", k, len(encoded)))
			out[bk] = fmt.Sprintf("[!] value omitted: %d bytes, over the %d-byte limit",
				len(encoded), maxAuditMetadataValueBytes)
		default:
			out[bk] = md[k]
		}
	}
	return out
}

// backstopEvent enforces maxAuditRecordBytes on the marshalled record.
//
// The per-field bounds above sum to well under the cap for any plausible event, so
// reaching this is either a field nobody enumerated or a producer with far more
// metadata keys than expected. Either way the answer is the same: keep the fields
// that identify the access decision — which is what the record exists for and what
// a caller refusing a login needs it to contain — and say that the rest went.
//
// A marshal failure is left alone. writeEvent marshals next and reports it, and
// that path is tested; guessing at a repair here would only hide it.
func backstopEvent(event AuditEvent) AuditEvent {
	data, err := json.Marshal(event)
	if err != nil || len(data) <= maxAuditRecordBytes {
		return event
	}

	note := fmt.Sprintf("[!] record was %d bytes, over the %d-byte limit; "+
		"groups and metadata were dropped to fit", len(data), maxAuditRecordBytes)
	event.Groups = nil
	event.Metadata = map[string]interface{}{auditTruncationKey: note}

	// Still over, with no groups and no metadata left: the remaining fields are the
	// bounded scalars, whose sum is under a few KiB, so this cannot happen from the
	// paths above. Returned as it is rather than mangled further — writeEvent will
	// write it, and a record slightly over a self-imposed cap is better than one this
	// function invented.
	return event
}
