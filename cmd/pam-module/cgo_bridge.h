#ifndef CGO_BRIDGE_H
#define CGO_BRIDGE_H

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

// PAM module name and version.
//
// The version and the build stamp arrive as -D macros from the Makefile — see
// PAM_VERSION_FLAGS there. They used to be Go link-time symbols set with
// `-ldflags -X main.version=...`, which stopped meaning anything when the module
// stopped being built by Go (issue #65): there is no main package left for the
// linker to write into.
//
// Both have a fallback so that a bare `cc cgo_bridge_linux.c` with no -D still
// compiles — test/cbridge does exactly that. The fallback says "dev" rather than a
// version number on purpose: a literal here would be a second place a release
// version is written down, and it would be wrong for every build that did not
// remember to update it.
#define PAM_MODULE_NAME    "oauth2_pam"

#ifndef PAM_MODULE_VERSION
#define PAM_MODULE_VERSION "dev"
#endif

// PAM_MODULE_BUILD is the commit and build date, logged next to the version so an
// operator reading syslog can tell which artifact is installed.
#ifndef PAM_MODULE_BUILD
#define PAM_MODULE_BUILD "unstamped"
#endif

// The wire contract this module speaks, sent as protocol_version in every
// request and checked against the broker's reply. Specified in
// docs/wire-protocol.md; must agree with internal/ipc.ProtocolVersion.
//
// A broker replying with a version above this one is refused rather than
// interpreted: the fields would still parse, and that is exactly the danger —
// "status" meaning something new is not detectable by reading it.
#define PROTOCOL_VERSION 1

// Buffer sizes. A device-flow response carries the verification URL, the user
// code and a QR code drawn with multibyte block characters, which puts it in
// the 2-3 KB range; 16 KB leaves ample headroom without allowing an
// unbounded read.
#define MAX_RESPONSE_SIZE  16384
#define MAX_SOCKET_PATH    108

// The receive buffer is one byte larger than the largest response we accept, so
// that a response of exactly MAX_RESPONSE_SIZE bytes has somewhere to put its
// terminating NUL. Sizing it at MAX_RESPONSE_SIZE instead made the read loop
// stop one byte early and reject a complete 16383-byte response as "too large".
#define RESPONSE_BUF_SIZE  (MAX_RESPONSE_SIZE + 1)

// Cap on the QR art the module will render.
//
// The art arrives in its own qr_code field (see the struct below) and is drawn
// from verification_uri, which the broker refuses to encode above 200 bytes —
// maxQRCodeURLBytes in pkg/auth. A 200-byte URL measures 5610 bytes of block
// characters, so 8 KiB is the ceiling with room to spare, and no reply from a
// broker honouring that bound comes near it.
//
// It is a bound of the module's own rather than a restatement of the broker's: the
// broker's bound is on the URL and this one is on the bytes about to be copied into
// a fixed buffer here. Art that does not fit is dropped rather than truncated —
// half a QR symbol is not scannable, and a partial box on screen reads as a
// rendering bug rather than as "no QR code". The URL and the user code are in
// instructions either way, and those are what the user acts on.
#define MAX_QR_CODE_LEN    8192

// The device-flow prompt is the broker's instructions plus the QR art plus a short
// trailer, so it must be larger than the sum of the two fields — otherwise a
// maximal response would truncate away the "press Enter" line and leave the user
// with no idea what to do. Sized from the field caps rather than from what a reply
// can actually hold (the whole reply is capped at MAX_RESPONSE_SIZE, so
// instructions and qr_code together cannot really reach this), because a buffer
// whose safety depends on arithmetic done in another process is not bounded here.
#define MAX_PROMPT_SIZE    (MAX_RESPONSE_SIZE + MAX_QR_CODE_LEN + 128)

// Field caps for a parsed broker response.
#define MAX_STATUS_LEN      32
#define MAX_SESSION_ID_LEN  129   // broker sends 32 hex chars; IPC caps at 128
#define MAX_USER_ID_LEN     257   // IPC caps user_id at 256
#define MAX_ERROR_MSG_LEN   512
#define MAX_ERROR_CODE_LEN  64

// Caps for the fields the module reports about the login itself.
#define MAX_SOURCE_IP_LEN   46    // IPC caps source_ip at 45
#define MAX_HOSTNAME_LEN    254   // IPC caps target_host at 253

// Default socket path for the oauth2-pam broker. It matches
// server.socket_path's default in pkg/config, so an unconfigured module and an
// unconfigured broker meet. validate_socket_path additionally accepts the /run
// spelling of the same directory — see there.
#define DEFAULT_SOCKET_PATH "/var/run/oauth2-pam/broker.sock"

// Bounds for module arguments.
#define DEFAULT_POLL_INTERVAL 5
#define MIN_POLL_INTERVAL     1
#define MAX_POLL_INTERVAL     60
// 90s, not the 300s this used to default to. sshd's LoginGraceTime is 120s by
// default, so it disconnects the session first: a 300s default could never
// elapse, meaning the module's own deadline was dead code and the user saw an
// abrupt disconnect instead of the "authentication timed out" message. 90s
// leaves headroom under the grace period for the final poll and the PAM
// conversation. Raise both together — timeout=N above LoginGraceTime is not a
// longer login, just an unreachable branch.
#define DEFAULT_AUTH_TIMEOUT  90
#define MIN_AUTH_TIMEOUT      10
#define MAX_AUTH_TIMEOUT      900

// Per-connection socket deadlines, applied with SO_RCVTIMEO/SO_SNDTIMEO. Without
// them a broker that accepts the connection and then never answers — wedged,
// deadlocked, or stopped between accept() and write() — leaves the module blocked
// in recv() with no deadline of its own, and the login hangs until sshd's
// LoginGraceTime kills the whole session. The module's timeout= cannot help: it
// is only consulted between polls.
//
// The two phases get different values because they wait on different things. An
// authenticate request makes the broker call the provider, whose HTTP client
// allows 30s, so anything shorter would abort a slow-but-working device flow
// start. A check_session request only reads broker state and never leaves the
// host, so it has no business taking longer than a few seconds.
#define AUTH_IO_TIMEOUT       35
#define POLL_IO_TIMEOUT       10

// Wire error codes the module treats specially. RATE_LIMITED means "slow down",
// not "no" — see internal/ipc.ErrorCodeRateLimited, which documents it as part
// of the contract.
#define ERROR_CODE_RATE_LIMITED "RATE_LIMITED"

// RESPONSE_TOO_LARGE means the broker had an answer and it did not fit the reply
// cap, so it sent this instead of something the module could not parse (see
// writeResponse in internal/ipc and docs/wire-protocol.md). It says nothing about
// the user: the module has no answer, which is not the same as a "no".
#define ERROR_CODE_RESPONSE_TOO_LARGE "RESPONSE_TOO_LARGE"

// The key the session id is filed under with pam_set_data, so that the account
// stage can find what the auth stage authenticated.
//
// Namespaced with the module name because the PAM data namespace is shared by every
// module in a stack: a bare "session_id" is a name another module could plausibly
// choose, and then this module's account stage would re-check somebody else's
// handle.
#define SESSION_DATA_KEY PAM_MODULE_NAME "_session_id"

// Wire status values. These mirror the auth.Status* constants in the broker.
// "authorized" is the only value that grants access.
#define STATUS_PENDING    "pending"
#define STATUS_AUTHORIZED "authorized"
#define STATUS_DENIED     "denied"
#define STATUS_EXPIRED    "expired"
#define STATUS_ERROR      "error"

// module_options holds the parsed pam.d module arguments.
struct module_options {
    const char *socket_path;
    const char *provider;  // configured provider name, or NULL for the default
    int poll_interval;     // seconds between check_session calls
    int auth_timeout;      // seconds to wait for the user to authorize
    int debug;
};

// broker_response is a parsed IPC reply. Every string field is NUL-terminated
// and bounded; instructions is the largest field, which is why callers work
// with a heap-allocated instance.
struct broker_response {
    char status[MAX_STATUS_LEN];
    char session_id[MAX_SESSION_ID_LEN];
    char user_id[MAX_USER_ID_LEN];
    char error_code[MAX_ERROR_CODE_LEN];
    char error_message[MAX_ERROR_MSG_LEN];
    char instructions[MAX_RESPONSE_SIZE];
    // The ASCII QR code, which the reply carries in a field of its own and no
    // longer inside instructions. Empty when the broker sent none — which is a
    // perfectly ordinary pending reply, not an error: above a 200-byte
    // verification_uri it deliberately sends no art. See MAX_QR_CODE_LEN.
    char qr_code[MAX_QR_CODE_LEN];
    int  poll_interval;   // from metadata.polling_interval, 0 if absent
    int  success;         // the "success" boolean, for cross-checking status
    int  protocol_version; // the reply's protocol_version; 0 if absent, i.e. 1
};

// Prototypes implemented in cgo_bridge_linux.c (compiled into the .so)
void log_pam_message(int priority, const char *format, ...);
void log_pam_message_string(int priority, const char *message);

// connect_to_broker returns a connected socket with io_timeout applied to every
// send and receive on it, or -1. io_timeout is in seconds and must be positive.
int  connect_to_broker(const char *socket_path, int io_timeout);

int  get_user_info(pam_handle_t *pamh,
                   const char **username,
                   const char **service,
                   const char **rhost,
                   const char **tty);
// send_auth_request sends the initial authenticate request. provider may be
// NULL, which asks the broker for its default (first configured) provider.
int  send_auth_request(int sock,
                       const char *username,
                       const char *service,
                       const char *rhost,
                       const char *tty,
                       const char *provider);
int  send_check_session_request(int sock, const char *session_id);

// receive_auth_response reads until the broker closes the connection and
// NUL-terminates the result. It accepts at most response_size - 1 bytes; a
// longer response is rejected rather than silently truncated into invalid JSON.
int  receive_auth_response(int sock, char *response, size_t response_size);

int  validate_socket_path(const char *path);
int  display_message(pam_handle_t *pamh, const char *message);

// prompt_user runs one conversation round. echo controls whether the reply is
// echoed: pass 0 for PAM_PROMPT_ECHO_OFF, non-zero for PAM_PROMPT_ECHO_ON.
int  prompt_user(pam_handle_t *pamh,
                 const char *prompt,
                 char *response,
                 size_t response_size,
                 int echo);

// parse_broker_response parses a JSON reply into a freshly allocated
// broker_response. Returns 0 on success (caller frees *out), -1 on failure.
int  parse_broker_response(const char *json_text, struct broker_response **out);

#endif // CGO_BRIDGE_H
