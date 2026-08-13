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
make test-integration   # needs Docker; see test/integration/README.md
```

On macOS, add a second lint pass for the files a Mac never compiles
(`peercred_linux.go`, `cgo_bridge_linux.c`'s Go side):

```sh
GOOS=linux golangci-lint run ./...
```

Without it, `_linux.go` files are invisible to local lint and first fail in CI.

CI runs all of it on every push and pull request: Linux (where the module
compiles and `SO_PEERCRED` is real), macOS (where it must still build), lint, and
the container harness.

`make test-integration` is the only thing that exercises the PAM module in a real
PAM stack. Any change to `cmd/pam-module/` or to the IPC contract needs it.

## Two things that are easy to break

**A started device flow is not an authentication.** `Success == true` iff
`Status == StatusAuthorized`, and `UserID` is populated only then. This invariant
is the fix for the v0.1.x authentication bypass; `internal/ipc/e2e_test.go` and
the harness case `never_authorized` both fail if it regresses.

**The module must export its entry points.** cgo only compiles C belonging to a
package that is actually built. `make build` checks with `nm`, and the harness's
client image refuses to build without all six `pam_sm_*` symbols — because a
module missing them fails silently at build time and loudly at login.
