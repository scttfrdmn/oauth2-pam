# C bridge tests

Unit tests for `cmd/pam-module/cgo_bridge_linux.c` — the half of this project that
`go test ./...` cannot see, because it is C and because on macOS
`cmd/pam-module` is not compiled at all.

```
make test-cbridge          # native on Linux, in a Debian container elsewhere
test/cbridge/run.sh
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
| a peer that hangs up mid-request | without `MSG_NOSIGNAL`, `send()` raises SIGPIPE and **terminates sshd's pre-auth child** — a broker restart would drop the connection instead of failing the module |
| the assembled `authenticate` request | the module sent `PAM_RHOST` as `target_host` and never sent `source_ip`, so every audit record named the client as the target and left the origin blank |
| `error_code` parsing | `RATE_LIMITED` arrives as `status: "error"` and was treated as terminal, failing logins that were only being asked to slow down |
| `validate_socket_path` | `/run/oauth2-pam/` — where systemd's `RuntimeDirectory=` puts the socket — was refused as unsafe |

The SIGPIPE case is the one to watch: if it regresses, the test binary is
*killed* rather than failing, and `run.sh` exits 141.

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
