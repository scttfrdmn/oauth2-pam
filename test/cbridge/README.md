# C bridge tests

Unit tests for `cmd/pam-module/cgo_bridge_linux.c` — the half of this project that
`go test ./...` cannot see, because it is C and because on macOS
`cmd/pam-module` is not compiled at all.

```
make test-cbridge            # native on Linux, in a Debian container elsewhere
test/cbridge/run.sh

make test-cbridge-mutations  # and the check that these tests can fail
test/cbridge/mutations.sh
```

## What these cover that the container harness does not

`test/integration/` drives real `ssh` logins through this code and is the
authority on *does a login work*. It cannot reach the boundaries, because it
cannot make the broker misbehave in specific ways. These can, over a
`socketpair`:

| Case | The defect it pins down |
|---|---|
| a reply exactly `MAX_RESPONSE_SIZE` bytes long | the read loop stopped one byte early and rejected a complete response as "too large" |
| one byte over the limit | must be refused, not truncated into JSON that might still parse |
| a peer that accepts and then says nothing | without `SO_RCVTIMEO` the module blocks in `recv()` until sshd's `LoginGraceTime` kills the session; `timeout=` cannot help, it is only consulted between polls |
| a peer that sends one byte per timeout | `SO_RCVTIMEO` bounds each `recv()`, not the reply, so a drip-feeding peer extended the wait per byte and held the login open for as long as it liked; the bound is now one absolute deadline for the whole transfer |
| a peer that hangs up mid-request | without `MSG_NOSIGNAL`, `send()` raises SIGPIPE and **terminates sshd's pre-auth child** — a broker restart would drop the connection instead of failing the module |
| the assembled `authenticate` request | the module sent `PAM_RHOST` as `target_host` and never sent `source_ip`, so every audit record named the client as the target and left the origin blank |
| `error_code` parsing | `RATE_LIMITED` arrives as `status: "error"` and was treated as terminal, failing logins that were only being asked to slow down |
| `validate_socket_path` | `/run/oauth2-pam/` — where systemd's `RuntimeDirectory=` puts the socket — was refused as unsafe |
| `authorized_for` and `terminal_status_to_pam` | the grant decision had **no coverage of any kind**: `authorized_for() { return 1; }` was green in every suite here, and the harness drives an honest broker that can never answer "authorized" for the wrong user |

The SIGPIPE case is the one to watch: if it regresses, the test binary is
*killed* rather than failing, and `run.sh` exits 141.

## Whether these tests can fail

A green suite proves the code does what the tests say. It does not prove the
tests would notice if it stopped — and a regression test that cannot fail is
worse than no test, because it reads as protection.

`mutations.sh` is the check on that. For each of the defects above it
reintroduces the defect in a copy of the source under `$TMPDIR`, rebuilds, and
asserts the suite **fails**; a mutation the suite survives is reported as
`MISSED` and fails the run. Nothing in the working tree is touched, so an
interrupted run leaves no half-mutated file behind. Output on a healthy tree:

```
==> baseline
ok       unmutated suite passes

==> mutations, each of which must be caught
caught   send() without MSG_NOSIGNAL (killed by SIGPIPE)
caught   a full buffer means too large (exit 1)
           FAIL cbridge_test.c:129: rejected a complete 16384-byte response
...
```

Three ways a case can be inconclusive rather than reassuring, all reported as
failures rather than passes:

- `SETUP` — the mutation's pattern matched nothing, or the mutated source did not
  compile. The source has moved and the mutation is no longer reintroducing the
  defect it names. Editing the bridge will eventually cause this; fix the pattern
  in `mutations.sh` rather than dropping the case.
- `HUNG` — the suite did not finish within 120s. The failure mode of a deadline
  defect is a test that blocks on a peer which will never speak, so each build is
  run under `timeout`; a case that never answers is evidence about nothing.
- `BROKEN` — the *unmutated* baseline failed. Usually this means the run is not
  privileged, the socket case skipped, and a skip counts as a failure. Run it
  under `sudo`, as the Makefile target and CI do; the container path is already
  root.

Mutations are deliberately the specific defect each test was written against,
not machine-generated. This is a check that named regression tests still bite,
not a coverage metric.

## Notes

- The implementation is `#include`d, not linked, so the file-static helpers are
  reachable. This file is a second translation unit of the module, not a
  consumer of it.
- Compiled with `-Werror -Wall -Wextra -Wconversion`. The bridge does socket and
  buffer arithmetic across `ssize_t`, `size_t` and `int`, which is exactly where
  an implicit narrowing turns a bounds check into a no-op.
- One case binds a socket in `/run/oauth2-pam/`, because that is the only place
  `validate_socket_path` accepts, so it needs root. **A skipped case counts as a
  failure**; set `CBRIDGE_ALLOW_SKIP=1` to accept the gap deliberately. CI runs
  the suite under `sudo`.
- No test asserts anything about `pam_sm_authenticate` itself. It needs a real
  PAM handle and a real conversation function; that is what the container
  harness is for.
