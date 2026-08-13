#!/bin/sh
# Answers the module's device-flow prompt on behalf of a human.
#
# ssh runs this with the whole prompt as $1 (SSH_ASKPASS_REQUIRE=force makes it
# do so even when a tty is available) and reads the reply from stdout. The module
# discards the reply — pressing Enter is the whole signal — so an empty line is
# the correct answer.
#
# Environment:
#   PROMPT_LOG           file to append the prompt to, so a case can assert that
#                        the user code and verification URL actually reached the
#                        client (default /tmp/prompt.log)
#   AUTHORIZE_ON_PROMPT  when 1, approve at the fake GitHub *after* the prompt
#                        appears and before the reply is sent. This is the honest
#                        ordering: the broker cannot have seen an approval at the
#                        time it answered `authenticate`.
#   CONTROL_URL          base URL of the fake GitHub control API
set -eu

: "${PROMPT_LOG:=/tmp/prompt.log}"
: "${CONTROL_URL:=http://fakegithub:8080}"

{
    echo "--- prompt at $(date -u +%H:%M:%S) ---"
    printf '%s\n' "${1:-}"
} >>"$PROMPT_LOG" 2>/dev/null || true

if [ "${AUTHORIZE_ON_PROMPT:-0}" = "1" ]; then
    curl -fsS "$CONTROL_URL/control/authorize" >>"$PROMPT_LOG" 2>&1 || true
fi

# The reply itself: an empty line, standing in for a bare Enter.
echo ""
