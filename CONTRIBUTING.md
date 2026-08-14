# Contributing

## Tracking work

Work is tracked in GitHub issues, grouped two ways.

**Milestones** are releases. An issue belongs to the release that will contain
its fix; `v0.3.0` is where the next round of work is scoped. If an issue has no
milestone it has not been scheduled, which is a decision in itself and worth
making deliberately.

**Labels** are one type plus one or more areas:

| Type | |
|---|---|
| `bug` | it does not do what it says |
| `enhancement` | it does, and that is the problem |
| `documentation` | the code is right and the docs are not |
| `security` | it is exploitable, or it removes a way to be exploited |

| Area | |
|---|---|
| `pam-module` | `oauth2_pam.so` and its C bridge |
| `broker` | the daemon, session state, IPC |
| `mapper` | identity-to-Unix-user mapping tiers |
| `config` | schema, loading, validation |
| `testing` | the Go suite and the container harness |
| `tech-debt` | dead code, structure, build hygiene |

The [oauth2-pam roadmap](https://github.com/users/scttfrdmn/projects/67) board
holds open work only. Closed issues stay findable by milestone, so the board does
not need to be a history.

## Closing issues from commits

**One `Closes #N` per line.** GitHub closes only the first reference in a
comma-separated list, so `Closes #2, #3, #11` closes #2 and silently leaves the
other two open. `Refs #N` never closes anything — use it when a fix genuinely
spans commits, and close the issue by hand when the last one lands.

```
Closes #2
Closes #3
Closes #11
```

## Before you push

```sh
go build ./...          # must pass on macOS too — cmd/pam-module/main.go is cgo-free
go vet ./...
go test -race ./...
golangci-lint run ./... # version pinned in .github/workflows/ci.yml
gofmt -l ./cmd ./pkg ./internal ./test
make verify-linux       # the same sweep under Linux, with the cgo packages included
make test-cbridge       # C unit tests for the bridge; see test/cbridge/README.md
make test-integration   # needs Docker; see test/integration/README.md
```

Two more, if you touched `cmd/pam-module/` or a test that guards it. They are
slower, and CI runs them anyway, so they are not part of the list above:

```sh
make test-cbridge-mutations      # reintroduce each fixed bridge defect; the C tests must fail
make test-integration-mutations  # reintroduce the v0.1.x bypass; the harness must refuse the login
```

`make verify-linux` runs build, vet, `test -race` and lint in a container with the
PAM and json-c headers present. It matters because a Mac cannot compile
`cmd/pam-module` at all, so `go build ./...`, `go test ./...` and golangci-lint all
*silently skip* the most security-sensitive package in the repo — and
`peercred_linux.go` with it. It answers "does the Linux build compile and pass";
`make test-integration` answers "does a login work".

If you would rather not build the image, the narrower version is a lint pass for
the files a Mac never compiles:

```sh
GOOS=linux golangci-lint run ./...
```

Without one or the other, `_linux.go` files are invisible locally and first fail
in CI.

CI runs all of it on every pull request and on pushes to `main`: Linux (where the
module compiles and `SO_PEERCRED` is real), macOS (where it must still build),
lint, the container harness, and the two mutation checks. A push to a topic branch
runs nothing until it opens a pull request, so run the list above locally rather
than pushing to find out.

`make test-integration` is the only thing that exercises the PAM module in a real
PAM stack. Any change to `cmd/pam-module/` or to the IPC contract needs it.

`make test-cbridge` is the only thing that reaches the bridge's edge cases. The
harness runs real logins, but it cannot make the broker misbehave in a specific
way — go there for a reply that exactly fills the read buffer, a broker that
accepts and then goes silent, or one that hangs up mid-request. It compiles with
`-Werror -Wconversion`, and a skipped case counts as a failure. No scanner reads
this C: CodeQL runs with `languages: go`, so these tests are the whole of its
coverage.

If you rewrite one of those tests, run `make test-cbridge-mutations` — it puts each
of the six original defects back and fails if the suite still passes. A test that
cannot fail is worse than no test, because it reads as protection.

## Changing the wire protocol

**This project owns the broker↔module protocol.** It is specified in
[docs/wire-protocol.md](docs/wire-protocol.md), that document is normative, and
other projects in the family ([oidc-pam](https://github.com/scttfrdmn/oidc-pam))
consume it. Two consequences for you: an undocumented change here is a silent
change to somebody else's project, and a version number is not yours to invent
locally.

If you touch the shape of a request or a reply:

1. **Decide whether it is additive.** A new optional field or a new error code is
   additive. A new `status` value, a changed meaning, a field going from optional
   to required, or a removed field is **not** — that needs `ProtocolVersion`
   bumped in `internal/ipc/server.go` *and* `PROTOCOL_VERSION` in
   `cmd/pam-module/cgo_bridge.h`, which are asserted to agree. The compatibility
   table in the spec is the reference.
2. **Update the spec in the same commit.** Where the spec and the code disagree,
   the code is what runs and the spec is the bug — so do not let them disagree.
3. **Cover it from both ends.** Go side in `internal/ipc/e2e_test.go`, C side in
   `test/cbridge/cbridge_test.c`, and add a mutation to
   `test/cbridge/mutations.sh` if the new behaviour is a *refusal* — a check that
   cannot fail is worse than no check, because it reads as protection.

## Two things that are easy to break

**A started device flow is not an authentication.** `Success == true` iff
`Status == StatusAuthorized`, and `UserID` is populated only then. This invariant
is the fix for the v0.1.x authentication bypass; `internal/ipc/e2e_test.go` and
the harness case `never_authorized` both fail if it regresses.

**The module must export its entry points.** cgo only compiles C belonging to a
package that is actually built. `make build` checks with `nm`, and the harness's
client image refuses to build without all six `pam_sm_*` symbols — because a
module missing them fails silently at build time and loudly at login.
