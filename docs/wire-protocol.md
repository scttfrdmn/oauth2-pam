# The oauth2-pam broker IPC contract, version 1

This is the protocol spoken between a PAM module and an authentication broker
over a Unix domain socket.

## Ownership

**`oauth2-pam` owns this protocol. Other projects consume it.**

That sentence is the point of this section, and it is a deliberate change from how
the two projects were related before. `oauth2-pam` and its sister
[`oidc-pam`](https://github.com/scttfrdmn/oidc-pam) are the same program with
different identity providers, and both independently shipped the same
authentication bypass — a `pending` device flow reported as a success — because
neither had written down what `success` meant
([oauth2-pam#5](https://github.com/scttfrdmn/oauth2-pam/issues/5),
[oidc-pam#146](https://github.com/scttfrdmn/oidc-pam/issues/146)). Two peers
maintaining parallel copies of an unwritten contract is what produced that, and
two peers maintaining parallel copies of a *written* one would only slow down the
next occurrence. So there is one owner and one normative document.

Concretely:

- **This document is normative.** A consumer that disagrees with it is wrong,
  even where its own code is self-consistent.
- **Version numbers are allocated here.** No consumer invents a version. There is
  exactly one meaning of "version 1", and it is the one below.
- **The reference implementation is here**, in the same repository as the spec, so
  the two are changed in one commit and drift is a reviewable diff:
  `internal/ipc/server.go` (broker), `cmd/pam-module/cgo_bridge_linux.c`
  (client), with the constants `internal/ipc.ProtocolVersion` and
  `PROTOCOL_VERSION` in `cmd/pam-module/cgo_bridge.h`. A test asserts those two
  agree, and that this document names the current version.
- **A change starts as an issue here**, lands here with tests on both ends, and
  is then a thing consumers implement — not the other way round. Consumers are
  welcome to propose changes; they are the same issues, filed on this repo.
- **Within this repository, spec and code are expected to agree, and neither one
  automatically wins.** If they disagree that is a bug in one of them and worth an
  issue either way: the spec is what other people build against, and the code is
  what is actually running on somebody's SSH port. Do not silently "fix" the
  document to match a behaviour change.

Nothing here makes this project's *identity* handling normative for anyone.
`oidc-pam` is not expected to authenticate the way `oauth2-pam` does; it is
expected to speak the same socket. See
[oauth2-pam#17](https://github.com/scttfrdmn/oauth2-pam/issues/17) and
[oidc-pam#149](https://github.com/scttfrdmn/oidc-pam/issues/149).

## The rule everything else serves

> Access is granted only when `success` is `true` **and** `status` is
> `"authorized"`, and only for the account named in `user_id`.

Every other paragraph here is in service of that sentence. In particular:

- A started device flow is **not** an authentication. `status` is `"pending"`,
  `success` is `false`, and `user_id` is empty. Both projects got this wrong.
- A `status` a client does not recognise is **not** an authorization. Unknown
  means no.
- `user_id` must equal the account the login is for. The broker checks this
  before it activates a session; a client checks it again on the value it is
  about to act on. Two independent checks, because one of them is in a different
  process and might be an older version of itself.

## Transport

- **A Unix domain socket.** No TCP, ever: the peer's identity is the point of the
  transport, and `SO_PEERCRED` is what makes per-caller rate limiting possible.
- **Socket mode `0660`, in a root-owned directory mode `0750`.** In this project's
  packaging the broker runs as `root:root`, so **only root can reach the socket**,
  and the module reaches it because it runs inside `sshd`'s pre-auth child. There
  is no group-based access model and no service account.

  This is worth stating precisely rather than leaving to packaging, because a
  reply is only as trustworthy as the question. Anything that can reach the socket
  can start device flows for any account and name session IDs the broker has never
  issued — a bounded, audited capability, but not nothing. An implementation that
  widens the socket beyond root is making a decision this specification does not
  make for it, and it should re-examine what it is relying on before doing so.
- **One request, one reply, one connection.** The client connects, writes exactly
  one JSON object, reads exactly one JSON object, and the connection is closed by
  the broker. There is no framing beyond that: the reply ends at EOF. There is no
  multiplexing, no keep-alive, and no server-initiated message.
- **A request is at most 64 KiB.** A receiver caps the read at that size instead
  of growing a buffer to fit, and refuses a larger request with
  `INVALID_REQUEST`.

  This used to say "refused before it is decoded", which no implementation of
  this framing can honour and none did: a request is a bare JSON object with no
  length prefix, so nothing on the wire announces its size in advance and a
  receiver learns a body is too long only by reaching the cap while reading it.
  What the cap guarantees is the **allocation**, not the ordering — and a receiver
  should say which of the two failed, because a body truncated at the cap looks
  to a JSON parser like malformed input, and a client told its serialization is
  broken will not go looking at the size of what it sent.
- **A reply is at most 16 KiB.** A client is entitled to refuse a larger one
  rather than grow a buffer without bound, and this one does: `MAX_RESPONSE_SIZE`
  in `cmd/pam-module/cgo_bridge.h` is 16384, and `strncpy` past it truncates in
  silence, which a client cannot then parse. This broker holds itself to the same
  number and substitutes `RESPONSE_TOO_LARGE` rather than writing an oversized
  reply — see that code below.
- **Both ends apply deadlines to every send and receive.** A broker that accepts
  a connection and then says nothing must not be able to hang a login: the client
  is inside `sshd`'s `LoginGraceTime` and has no other timer for a blocked
  `recv()`. The broker's are `server.read_timeout` / `server.write_timeout`; the
  client's are per phase, because starting a device flow involves a provider
  round trip and polling does not.

The largest reply by a wide margin is the first one, and the reason is the QR
code: ASCII art in multibyte block characters, whose size grows superlinearly in
the length of the URL it encodes, and the URL is `verification_uri` from the
provider. Measured against the real `github.com/skip2/go-qrcode` at Medium
recovery, serializing the reply this broker sends (JSON plus the trailing
newline), with a lowercase URL because that is what puts the encoder in byte mode
and byte mode is the larger of the two encodings a real URL can take:

| `verification_uri` | QR art | first reply |
|---|---|---|
| 31 B — what github.com actually sends | 1940 B | **2.9 KB** |
| 51 B — a URI with the user code in it | 2304 B | 3.3 KB |
| 200 B — the ceiling, above which no QR is drawn | 5610 B | 6.9 KB |
| longer than 200 B | none | ~1.4 KB plus the URL, which appears twice |

Earlier revisions of this document said "around 2–3 KiB in practice", which was
wrong on the happy path in the direction that made 16 KiB look generous: that
figure was the size of the `instructions` field, while the reply carried the same
art a second time in `qr_code`, so the real github.com baseline was 4.9 KB before
any hostile input — and a 300-byte `verification_uri` reached 17.6 KB, over the
buffer, while a 2 KB one reached 88 KB
([#56](https://github.com/scttfrdmn/oauth2-pam/issues/56)). Both halves of that
are fixed rather than re-documented: the art is serialized once, in `qr_code`, and
the URL it is drawn from is bounded at 200 bytes with the code skipped above that.
The sizing rule a consumer should take from it is to measure the whole reply
rather than one field, and to remember that the largest field in it is a function
of a string the provider chose the length of.

That is also why the QR bound is not the whole answer. The URL itself is on the
wire twice, in `device_url` and inside `instructions`, so a provider sending a
multi-kilobyte `verification_uri` still writes a reply that will not fit — around
7.7 KB of URL is enough. What it gets is the reply cap: `RESPONSE_TOO_LARGE`, which
is a terminal answer with a reason in it, rather than a truncated object the client
cannot parse.

The figures above are all the **pending** reply, which is the largest one and was
for a while the only one anybody had measured. The **authorized** reply carries
three fields this broker does not choose the length of — `email` and
`metadata.provider_login` come from the provider, and `groups` comes from a mapper
tier whose own response limit is 1 MB — and none of them was bounded, so an
authorized reply could exceed the cap on its own
([#88](https://github.com/scttfrdmn/oauth2-pam/issues/88)). That was worse than a
failed login: `RESPONSE_TOO_LARGE` is terminal for the attempt, but the session
behind it stayed authorized, counted toward `max_concurrent_sessions` and held a
live token for `token_lifetime`, so a handful of attempts locked the account out
for hours behind sessions no client could resolve. The three fields are now bounded
where the reply is composed — 320 bytes of `email`, 256 of `provider_login`, and a
group list capped at 64 entries and 3072 bytes total — which puts a worst-case
authorized reply at about 4 KB, a quarter of the cap. Two consequences a client
should know about:

- Those budgets are counted in **encoded** bytes: what each character costs after
  `json.Marshal`, not what it costs in the value. JSON escaping is not
  size-preserving, and control characters are not the only characters that expand —
  Go's encoder writes `&`, `<`, `>` and U+2028/9 as six-byte `\uXXXX` escapes with
  HTML escaping on, which is the default. Counting composed bytes was
  [#92](https://github.com/scttfrdmn/oauth2-pam/issues/92): a group list of
  ampersands measured 3072 bytes against the budget and serialized to 18432, past
  the whole reply cap on its own, which put #88's lockout straight back. Counted
  after escaping, a maximal reply measures the same ~4 KB whatever its characters
  are. Control characters are still stripped rather than escaped, so a client will
  not see them at all.
- An over-budget `groups` is omitted entirely and `metadata.groups_omitted` is set
  to `"true"`. A truncated list is indistinguishable from a complete one, and a
  client acting on membership would act on a list missing whichever entries sorted
  last. Omission is at least honest.

Neither is a new protocol version: `groups_omitted` is an added `metadata` key,
which the extension rules below already permit, and a receiver that ignores it sees
a reply it can still parse and act on.

## Versioning

The version of this contract is an integer. Version 1 is what is described here.
It is what `oauth2-pam` has spoken since v0.2.0, retroactively named: the
`protocol_version` field itself is new in v0.3.0, and the behaviour it names is
older than the field.

Whether any other implementation currently conforms to version 1 is a question
about that implementation, and this document does not answer it. Do not read
"version 1" as a claim that every project in the family already speaks it.

- A request **may** carry `protocol_version`. Absent, or `0`, means 1 — a client
  predating the field speaks version 1 by definition, and must keep working.
- A reply **must** carry `protocol_version`, including replies that are errors
  produced before the request was dispatched.
- A broker receiving a version it does not implement refuses the request with
  `error_code: "UNSUPPORTED_PROTOCOL"` and does no work. This is terminal, not
  retryable.
- A client receiving a version it does not implement **must not grant access.**
  It is a transport failure, not a decision about the user. The reason to refuse
  is not that the reply fails to parse — it is that it parses fine and
  `"authorized"` may mean something new.
A malformed `protocol_version` is where the two ends of this implementation
legitimately differ, and the difference is worth stating rather than papering
over. Both fail closed; they close in different directions because they are
protecting different things.

| Value | Broker reading a request | Client reading a reply |
|---|---|---|
| absent, or `null` | version 1 | version 1 |
| `0` | version 1 | version 1 |
| a negative integer | `UNSUPPORTED_PROTOCOL` | refused |
| a string, or a non-integral number | `INVALID_REQUEST` — the whole request fails to decode | read as absent, so version 1 |

The broker refuses the request outright because a client that cannot serialize an
integer has told it nothing trustworthy about anything else in the object. The
client is more forgiving in that one spot on purpose: a v0.2.x broker sends no
`protocol_version` at all, and an in-place upgrade of the module must not break
against one. What must never happen at either end is nonsense being treated as a
*known* version other than 1.

Compatibility within a version is **additive only**:

| Change | Needs a new version? |
|---|---|
| A new optional field | No. Receivers ignore fields they do not know. |
| A new `status` value | **Yes.** A client that does not know it will refuse the login, which is safe but is a behaviour change. |
| A new `error_code` | No, provided its retryability is discoverable — see below. |
| A new request `type` | No. An unknown type is refused. |
| Changing what an existing field means | **Yes.** This is the change the version number exists for. |
| Making an optional field required | **Yes.** |
| Removing a field | **Yes.** |

### Extension fields

A consumer will have fields this spec does not define — `oidc-pam` carries
`ssh_public_key` and `risk_score`, neither of which means anything here. That is
allowed, and needs no version bump, under three rules:

1. **A receiver ignores fields it does not know.** This is what makes the whole
   additive-compatibility story work, so it is not optional.
2. **An extension field must never be load-bearing for the authorization
   decision.** If a field can turn a non-grant into a grant, it is part of the
   contract and belongs in this document, at a new version. An implementation
   whose access decision depends on a field a conformant peer would discard is not
   speaking version 1, whatever it puts in `protocol_version`.
3. **Register it here once it is shared.** The moment a second implementation
   reads a field, it stops being an extension and becomes contract. File an issue
   on this repo and it gets a row in the tables below.

Rule 2 is the one with teeth, and it is not hypothetical: `requires_device` was
exactly such a field. Making the grant depend on it is what version 1 replaced
with `status`.

| Field | Type | Notes |
|---|---|---|
| `protocol_version` | int | Optional. Absent means 1. |
| `type` | string | `authenticate`, `check_session`, `refresh_session`, `revoke_session`. Anything else is refused. |
| `user_id` | string | The **local account being logged into** — the PAM username, not the provider's. Required and non-empty for `authenticate`. Max 256 bytes, no NUL. |
| `session_id` | string | Required for the session verbs. Max 128 bytes, no NUL. |
| `provider` | string | Optional. Names a configured provider; absent means the broker's default. A name that is not configured is refused rather than replaced by the default. Max 256 bytes, no NUL. |
| `source_ip` | string | The client address, if the login has one and it really is an address. Max 45 bytes (an IPv6 literal with a scope), no NUL. A resolved hostname does not belong here. See below: a receiver **must** accept a zone, and an absent value means *origin unknown*. |
| `target_host` | string | The host being logged **into** — this host. Max 253 bytes, no NUL. |
| `login_type` | string | `ssh`, `console`, or `gui`. Optional; empty is treated as `ssh`. Any other value is refused. It selects how instructions are formatted, nothing more. |
| `user_agent` | string | Optional, carried into the audit trail. Max 512 bytes, no NUL. |
| `device_id` | string | Optional, carried into the audit trail. Max 256 bytes, no NUL. |
| `metadata` | object of string→string | Optional. Free-form context for the audit trail: this client sends `service`, `tty`, `pid`, and the unabridged `rhost`. At most 64 entries, keys max 128 bytes, values max 1024 bytes. No NUL in keys or values. |

Every string above is bounded, including the fields a broker only stores: a
maximum length *and* no embedded NUL, except for `type` and `login_type`, where
the enumeration is a tighter bound than either. Both halves of that were missing
here before v0.4.0 — `user_agent` and `device_id` had no maximum stated and none
enforced, so a 64 KiB `user_agent` became a 64 KiB audit record written by
whatever reached the socket, and `metadata` had no bound on its entry count at
all.

The NUL rule matters most for the fields nothing interprets. The reference client
is C, where a NUL ends a string, so a value carrying one can be audited as one
thing and acted on as another; `source_ip` and `target_host` in particular are
copied into an audit event unaltered. A conformant client never sends one, which
is the point: refusing it is a receiver declining to fail open, not a constraint
on anybody's client.

The maxima are ceilings on what reaches an audit record and a log line, not a
budget a client is expected to manage. They are sized well above anything a real
client sends — the reference client's `metadata` has four entries — so a receiver
that has to refuse one is looking at something that is not a login.

Note the two easily-confused fields. `user_id` in a *request* is the local account
being asked for; `user_id` in a *reply* is the local account the broker
authorized. The whole authorization decision is that those two agree, so a client
that conflates them has no check left. `source_ip` is where the login came from
and `target_host` is where it is going; this project shipped them backwards once,
which made every audit record name the client as the host being logged into.

#### `source_ip`, in three parts

All three of these were silences in this document that cost a real implementation a
real bug (`oidc-pam#169`, where both ends sent `PAM_RHOST` as `target_host` and no
`source_ip` at all). They are stated normatively because a client cannot otherwise
know whether what it sends is safe.

**A receiver must accept a zoned IPv6 literal.** `fe80::1%eth0` is inside the
45-byte bound and is what a link-local login looks like, but the obvious validator
rejects it: Go's `net.ParseIP` fails on a zone and C's `inet_pton(AF_INET6, …)`
fails on one too. So a broker that validates the naive way refuses a login whose
length this table explicitly sized for. Strip the zone, validate the address,
and — if the value is forwarded or logged — forward it with the zone intact: the
zone is which interface the peer is on, which is not redundant with the address.

**An absent `source_ip` means the origin is unknown, and unknown is never
equivalent to a satisfied network requirement.** A console login genuinely has no
source address, so absence is legitimate and a broker must not treat it as a
malformed request. But a broker enforcing something like "private networks only"
cannot answer that requirement from an absent value, and both of the readings it
might reach for on its own are silent failures: treating absent as *not* private
refuses every console login and reports the origin as public when it is merely
unknown, and treating absent as *satisfying* the requirement makes the requirement
bypassable by omitting one optional field.

This document does not choose the resolution — deny by default, or an explicit
operator waiver, is a broker's policy decision. What it fixes is the premise: an
absent value is `unknown`, a third answer, and a network requirement is not met by
it. A broker that has such a requirement configured must decide what `unknown`
does *before* it can be asked, and say so in its own configuration rather than
arriving at it by accident inside a validator.

**`metadata.rhost` may be a resolved hostname.** That is the reason the
address-only restriction on `source_ip` is affordable: a hostname is not discarded,
it moves to a field nothing decides on. Which is also the constraint — by rule 2 of
the extension rules, a receiver must not read `metadata.rhost` for an
authorization decision. It is audit context. If a peer ever needs a hostname to
decide something, that is a new field in this document at a new version, not a
reinterpretation of this one.

### `authenticate`

Starts a device flow. This is the expensive verb — a provider round trip, a
polling goroutine, and state that outlives the connection — so it is rate limited
per calling UID.

The reply is `status: "pending"` with a `session_id` to poll, the user-facing
`instructions`, and `metadata.polling_interval` (seconds, **as a string**, because
`metadata` is a string map). A client should honour that interval; it is the
provider's, not an invention of the broker's.

### `check_session`

Polls one session. Rate limited per session rather than per caller: a poll's cost
belongs to one login, and charging it to the caller made every login on the host
share one budget. Returns the session's current status.

### `refresh_session`

Extends the lifetime of an authorized session. **No provider round trip is
involved** — this verb does not exchange an OAuth2 refresh token, and a broker is
not required to hold one; it moves the broker's own `expires_at` and nothing else.
Earlier revisions of this document said otherwise, which was wrong about every
implementation including this one.

A refresh is an extension of something still live, never a second chance at an
authorization, so four things are refused rather than extended:

- A session that is not authorized — pending, denied, expired, errored — with
  `SESSION_NOT_ACTIVE`.
- A session that **has already expired**, with `status: "expired"` and
  `SESSION_EXPIRED`. The session is removed, so a second attempt gets
  `SESSION_NOT_FOUND`. This is the same answer `check_session` gives, and the two
  verbs are required to agree: a broker that extends an expired session lets a
  client route around its own expiry by choosing which verb to send. This broker
  did exactly that until v0.3.0.
- A session **past the broker's absolute age ceiling**, also with
  `SESSION_EXPIRED`. A ceiling is measured from when the session was created and
  no extension moves it, so however often a client refreshes, a session cannot
  outlive it; reaching it revokes the token at the provider. Whether there is such
  a ceiling and how long it is are the broker's policy — `security.max_token_age`
  here — and a client must not infer one from `expires_at`.
- A session whose **access token is no longer usable**, also with
  `SESSION_EXPIRED`. The session is what authorizes use of a credential, so a
  session outliving its credential is a shell and must not be reported as
  authorized. One consequence is worth stating because it is easy to meet by
  accident: a broker that never extends the stored token's own lifetime will
  refuse a second refresh once that lifetime has passed, so refresh is not
  indefinitely repeatable even below the age ceiling.

A client cannot tell those last three apart, deliberately: all of them mean this
session is over, start a new `authenticate`. `error_message` says which, for the
log.

### `revoke_session`

Ends a session and revokes the token at the provider. The reply's `status` is
`"revoked"`, which is not a session state — the session no longer exists — but
every reply carries a status so a client never has to special-case a missing one.

## Replies

One JSON object.

| Field | Type | Notes |
|---|---|---|
| `protocol_version` | int | Always present. |
| `status` | string | **Authoritative.** See below. |
| `success` | bool | True only when `status` is `"authorized"` (or `"revoked"` for a revocation). Redundant with `status` on purpose: it is the field the pre-status clients read, and a client should require both to agree. |
| `user_id` | string | The local account authorized. Populated **only** when authorized. |
| `session_id` | string | The handle to poll. |
| `instructions` | string | Ready-to-display text for the user, formatted for `login_type`. A client is not expected to build this from the parts. It carries the URL and the user code as text and **does not embed the QR code** — see below. |
| `device_code`, `device_url`, `qr_code` | string | The parts, for a client that wants to format its own prompt. `qr_code` is the only place the QR art travels, and it is empty when there is none. |
| `expires_at` | RFC 3339 timestamp | When the session or the flow expires. |
| `error_code` | string | Machine-readable. See below. |
| `error_message` | string | For the log, not for a decision. |
| `groups` | array of string | **Advisory.** The mapper's supplementary groups. This client discards them and nothing calls `setgroups(2)`. See [#39](https://github.com/scttfrdmn/oauth2-pam/issues/39). Bounded, and **dropped whole rather than truncated** when it does not fit — see the reply size budget. |
| `email` | string | Optional, informational. At most 320 bytes. |
| `requires_device`, `requires_approval` | bool | Legacy hints from before `status` existed. Do not make decisions on them. |
| `metadata` | object of string→string | `polling_interval` on a pending reply, `provider` and `provider_login` where known, `groups_omitted: "true"` when `groups` was dropped for size. A receiver must treat an absent `groups` with `groups_omitted` set as "unknown membership", not as "no groups". |

The QR code appears **once** in a reply, in `qr_code`. It used to be there and
inside `instructions` as well, which put the largest field of the largest reply on
the wire twice at a size the provider chose; a client that wants to draw a QR code
renders that field. `qr_code` may also be empty on a perfectly good `pending`
reply — a broker that will not encode an overlong `verification_uri` is expected to
send none rather than to fail the login — so a client must treat the art as
optional and the URL and code in `instructions` as what the user acts on.

### Status values

| `status` | Meaning | Terminal? | Grants access? |
|---|---|---|---|
| `pending` | A device flow is started and nobody has approved it yet | no | **no** |
| `authorized` | Approved, identity mapped, and the mapping matches the requested account | yes | **yes**, with `success: true` |
| `denied` | Refused: the user denied it at the provider, the identity mapped to a different account, or the mapping was refused | yes | no |
| `expired` | The flow or the session ran out of time | yes | no |
| `error` | Something failed, or the broker is full. Read `error_code` | yes, unless the code says otherwise | no |
| `revoked` | Reply to `revoke_session` only | yes | n/a |

**A capacity refusal is `error`, never `denied`.** Running out of capacity —
`SESSION_LIMIT_REACHED` or `AUTH_LIMIT_REACHED` — is a statement about the
broker's load, not a judgement about the identity presenting itself: nobody was
refused, the broker declined to try. `denied` is reserved for the three things in
its row above, all of which are decisions about *this* user, and a client is
entitled to treat it as one. This broker sent `denied` with
`SESSION_LIMIT_REACHED` until v0.4.0, so the same condition — this host is full —
arrived as a decision about the user down one path and as an operational failure
down the other; a user at their session cap was told their identity had been
refused, and the module mapped it to `PAM_AUTH_ERR` rather than the
`PAM_AUTHINFO_UNAVAIL` its twin got ([#84](https://github.com/scttfrdmn/oauth2-pam/issues/84)).
The two codes stay distinct so a log can tell them apart; the status they arrive
with does not.

A terminal session remains queryable for a grace period after it ends — two
minutes in this broker — so a client that is still polling learns the real outcome
instead of `SESSION_NOT_FOUND`. Deleting the session immediately turned every
denial into "not found", which is indistinguishable from a broker restart. Do not
rely on the specific length; do rely on one poll after a terminal outcome getting
the outcome.

An unrecognised `status` must fail closed. This client logs it and returns
`PAM_AUTH_ERR`.

### Error codes and retryability

`error_code` exists because `status: "error"` alone cannot be acted on. Every
error arrives as `status: "error"`, so without reading the code a client cannot
tell "slow down" from "no".

The one code whose retryability is part of the contract:

- **`RATE_LIMITED` means "slow down", not "no".** Treating it as terminal fails
  logins that were only being throttled. **Which phase it arrives in decides what
  to do**, and the two answers are different:
  - On a **`check_session`** poll it is neither a failure nor an answer. Back off
    (this client doubles, capped at `MAX_POLL_INTERVAL`) and keep polling. It must
    *not* be charged to the transport-failure budget: three tries at the normal
    interval are over in fifteen seconds, well inside the limiter's one-minute
    window, so a login would die for a condition that clears on its own. The
    overall deadline is what bounds the wait.
  - On **`authenticate`** it is effectively terminal for this login. The window is
    a fixed minute and the login does not have a minute to spend, so this client
    reports it and stops rather than retrying.
- **`UNSUPPORTED_PROTOCOL` is terminal.** Retrying the same version gets the same
  answer.

**Capacity conditions — `AUTH_LIMIT_REACHED` (the host's concurrent device flows)
and `SESSION_LIMIT_REACHED` (this user's active sessions) — both arrive as
`status: "error"`, and neither is retried.** The status is the same for both
because the condition is the same: the broker is at a limit and declined to try,
which is a fact about the host's load and not a decision about the identity that
asked (see Status values above, and
[#84](https://github.com/scttfrdmn/oauth2-pam/issues/84)). They keep separate
codes because they are worth telling apart in a log — one is this user's own
sessions, the other is every login on the host — not because a client should act
on them differently. `AUTH_LIMIT_REACHED` in particular is held by *other* logins
for as long as their device flows live, so retrying inside this login only spends
the user's remaining time to fail again.

The remaining codes are diagnostic. A client that does not recognise a code must
treat the reply as a failure, which for all of these is the right answer:

| Code | Sent by | Means |
|---|---|---|
| `INVALID_REQUEST` | broker, pre-dispatch | the request did not decode, or a field was out of bounds |
| `INVALID_REQUEST_TYPE` | broker | unknown `type` |
| `NO_PROVIDER` | broker | `provider` names something not configured |
| `DEVICE_FLOW_FAILED` | broker | the provider refused to start a device flow |
| `SESSION_NOT_FOUND` | broker | no such `session_id`, or it aged out past the grace period |
| `SESSION_EXPIRED` | broker | the session or device code ran out of time |
| `SESSION_NOT_ACTIVE` | broker | a session verb was used on a session that is not authorized |
| `SESSION_LIMIT_REACHED` | broker | this user already has as many active sessions as the broker allows. `status: "error"` — capacity, not a denial |
| `AUTH_LIMIT_REACHED` | broker | the host already has as many device flows in progress as the broker allows. `status: "error"` for the same reason |
| `AUTHENTICATION_FAILED`, `SESSION_CHECK_FAILED`, `SESSION_REFRESH_FAILED`, `SESSION_REVOCATION_FAILED` | broker | the verb's handler returned an internal error; details are in the broker's log, deliberately not on the wire |
| `RESPONSE_TOO_LARGE` | broker | the reply for this request did not fit the reply cap and was replaced by this one. Terminal |

`RESPONSE_TOO_LARGE` is registered here because `oidc-pam` sends it (`oidc-pam#162`:
an 8 KiB client buffer against a reply whose QR art was serialized twice refused
every login on the host, with nothing in the log but "failed to parse broker
response"), and by rule 3 above a code a second implementation reads is contract
rather than dialect. A client that gets it learns the difference between "the broker
sent something I could not parse" and "the broker had something to say and it did
not fit" — which is the whole value of substituting it.

Whether a version-1 broker is *obliged* to substitute it, rather than writing an
oversized reply and leaving the client to refuse, is not settled here: that is a
requirement on brokers, and specifying it is
[#48](https://github.com/scttfrdmn/oauth2-pam/issues/48). Sending it is permitted
today; relying on receiving it is not. This broker does substitute it, as of the
fix for [#56](https://github.com/scttfrdmn/oauth2-pam/issues/56) — every reply is
serialized and measured before it is written — which is a property of this
implementation and not yet a promise of version 1.

## What this contract deliberately does not do

Stated because their absence is a design decision, not an oversight:

- **No cryptographic binding between the approval and the connection.** Nothing
  in a reply proves the person who approved at the provider is the person on the
  other end of the SSH connection. The device authorization grant has no field to
  put a connection fingerprint into. See
  [#33](https://github.com/scttfrdmn/oauth2-pam/issues/33).
- **No authentication of the broker to the client.** The socket's path and mode
  are the trust anchor; a client that can be pointed at a different socket by an
  unprivileged user has already lost, which is why the client here refuses a
  socket path outside the expected directory.
- **No session reuse.** Every `authenticate` starts a new flow. The contract
  allows a broker to answer `authorized` immediately — this client handles that
  reply — but no broker does. See
  [#34](https://github.com/scttfrdmn/oauth2-pam/issues/34).
- **No batch or streaming operations.** One request, one reply.

## Conformance

A consumer claiming to speak version 1 must satisfy all of the following. They are
written as things to *test*, not things to intend, because every item here is
something at least one implementation in this family has got wrong.

A **client** (PAM module):

1. Grants access only on `success == true` **and** `status == "authorized"`.
2. Refuses a `status` it does not recognise, and refuses `pending` — including
   the first reply to `authenticate`, which is always `pending`.
3. Compares the reply's `user_id` against the account being logged into, and
   refuses a mismatch. Yes, the broker checks this too. That is the point.
4. Sends `protocol_version`, and refuses a reply whose version it does not know
   rather than interpreting its fields.
5. Treats an absent reply `protocol_version` as 1, so it works against a broker
   predating the field.
6. Distinguishes `RATE_LIMITED` from a denial, and backs off on a poll rather than
   failing the login.
7. Applies a deadline to every send and receive, so a broker that accepts a
   connection and then goes silent cannot hang the login.
8. Bounds the reply it will read instead of growing a buffer to fit.

A **broker**:

1. Answers `authenticate` with `success == false`, `status == "pending"`, and an
   empty `user_id`. Never anything else, however fast the provider is.
2. Enforces the mapped-account-equals-requested-account rule itself, and refuses
   an `authenticate` with an empty `user_id` rather than activating as whatever
   the identity maps to.
3. Stamps `protocol_version` on **every** reply, including errors emitted before
   the request is dispatched.
4. Refuses an unknown request `protocol_version` with `UNSUPPORTED_PROTOCOL`, and
   does no work for it.
5. Keeps a terminal session queryable long enough for one more poll to see the
   outcome.
6. Bounds every request field — a maximum length *and* no embedded NUL, for each
   one, including the fields it only stores — and caps the request read at 64 KiB
   so an oversized request is refused rather than buffered. This item is written
   as "every field" rather than a list because that is how it was got wrong: the
   broker here bounded the fields somebody thought to bound, and `user_agent`,
   `device_id` and the `metadata` entry count were not among them. Test it
   against the struct the request decodes into, not against the table above.
   ("Before decoding" is what this item used to require of the size cap; see
   Transport for why that is not achievable for this framing, and what is
   required instead.)
7. Never puts internal error detail on the wire. `error_code` is a category;
   the detail belongs in the broker's log.
8. Accepts a zoned IPv6 `source_ip` — a validator that rejects `fe80::1%eth0`
   refuses a login this contract sized a field for.
9. Never satisfies a network requirement from an absent `source_ip`. Absent is
   `unknown`, and what `unknown` does is a decision the broker must have made
   before it is asked, not one a validator makes for it by returning false.
10. Reports a capacity refusal as `status: "error"`, whichever limit was reached,
    and keeps `denied` for decisions about the identity. Test both limits in one
    test: the way this was got wrong was two refusals of the same shape written in
    different places, each self-consistent.

Both ends: **an extension field is never load-bearing for the grant.** Not a
separate item because it is not a separate test — it is the property the other
items are protecting, and the way to check it is to delete the field and see
whether the decision changes.

## Testing this contract

Both halves are exercised in this repository, and the claim is meant to be
checkable rather than taken on trust. A consumer is welcome to lift these as a
starting point — the conformance list above is what they are checking:

- `internal/ipc/e2e_test.go` drives a real broker over a real socket against a
  fake provider, including that `authenticate` is not an authentication, that a
  mapping to a different account does not authorize the requested one, that every
  reply carries `protocol_version`, and that an unsupported version is refused.
- `internal/ipc/reply_size_test.go` covers the sizing claims above with the real
  QR encoder: that the art is serialized exactly once, that a `verification_uri`
  from anywhere in the range that used to overflow the client's buffer cannot
  inflate a reply past the cap, and that an oversized reply is replaced by
  `RESPONSE_TOO_LARGE` rather than written.
- `test/cbridge/cbridge_test.c` covers the client's parsing and serialization:
  which field carries what, a reply exactly the size of the buffer, a broker that
  accepts and then says nothing, and the version rules above.
- `test/cbridge/mutations.sh` reintroduces each defect this contract's wording
  exists to prevent and requires the tests to fail — including a version check
  that accepts everything.
- `test/integration/` drives real `ssh` logins through a real PAM stack against a
  real broker.
