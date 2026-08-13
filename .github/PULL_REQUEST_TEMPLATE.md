## What this changes

<!-- And why. If it fixes an issue, use a `Closes #N` line per issue below —
GitHub closes only the first reference in a comma-separated list. -->

Closes #

## How it was verified

<!-- Name what you actually ran, not what would be reasonable to run. -->

- [ ] `go test -race ./...`
- [ ] `golangci-lint run ./...` and, on macOS, `GOOS=linux golangci-lint run ./...`
- [ ] `make build` — including the `nm` check for the six `pam_sm_*` entry points
- [ ] `make test-integration` — **required** if this touches `cmd/pam-module/`,
      `internal/ipc/`, or the response contract in `pkg/auth`
- [ ] not applicable, because:

## The two invariants

Tick these only if the change comes near them; say so if it does not.

- [ ] **A started device flow is still not an authentication.** `Success == true`
      iff `Status == StatusAuthorized`, and `UserID` is populated only then. This
      is the v0.1.x bypass; `internal/ipc/e2e_test.go` and the harness case
      `never_authorized` both fail if it regresses.
- [ ] **The module still exports its entry points.** cgo only compiles C
      belonging to a package that is actually built, so an innocuous-looking
      restructuring of `cmd/pam-module/` can produce a `.so` with no `pam_sm_*`
      symbols. That build succeeds and the module fails at login.

## Anything a reviewer should look at first

<!-- The part you are least sure about. -->
