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

// PAM module name and version
#define PAM_MODULE_NAME    "oauth2_pam"
#define PAM_MODULE_VERSION "0.2.0"

// Buffer sizes. A device-flow response carries the verification URL, the user
// code and a QR code drawn with multibyte block characters, which puts it in
// the 2-3 KB range; 16 KB leaves ample headroom without allowing an
// unbounded read.
#define MAX_BUFFER_SIZE    16384
#define MAX_RESPONSE_SIZE  16384
#define MAX_SOCKET_PATH    108

// The device-flow prompt is the broker's instructions plus a short trailer, so
// it must be larger than the instructions themselves — otherwise a maximal
// response would truncate away the "press Enter" line and leave the user with
// no idea what to do.
#define MAX_PROMPT_SIZE    (MAX_RESPONSE_SIZE + 128)

// Field caps for a parsed broker response.
#define MAX_STATUS_LEN      32
#define MAX_SESSION_ID_LEN  129   // broker sends 32 hex chars; IPC caps at 128
#define MAX_USER_ID_LEN     257   // IPC caps user_id at 256
#define MAX_ERROR_MSG_LEN   512

// Default socket path for the oauth2-pam broker
#define DEFAULT_SOCKET_PATH "/var/run/oauth2-pam/broker.sock"

// Bounds for module arguments.
#define DEFAULT_POLL_INTERVAL 5
#define MIN_POLL_INTERVAL     1
#define MAX_POLL_INTERVAL     60
#define DEFAULT_AUTH_TIMEOUT  300
#define MIN_AUTH_TIMEOUT      10
#define MAX_AUTH_TIMEOUT      900

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
    int poll_interval;   // seconds between check_session calls
    int auth_timeout;    // seconds to wait for the user to authorize
    int debug;
};

// broker_response is a parsed IPC reply. Every string field is NUL-terminated
// and bounded; instructions is the largest field, which is why callers work
// with a heap-allocated instance.
struct broker_response {
    char status[MAX_STATUS_LEN];
    char session_id[MAX_SESSION_ID_LEN];
    char user_id[MAX_USER_ID_LEN];
    char error_message[MAX_ERROR_MSG_LEN];
    char instructions[MAX_RESPONSE_SIZE];
    int  poll_interval;   // from metadata.polling_interval, 0 if absent
    int  success;         // the "success" boolean, for cross-checking status
};

// Prototypes implemented in cgo_bridge_linux.c (compiled into the .so)
void log_pam_message(int priority, const char *format, ...);
void log_pam_message_string(int priority, const char *message);
int  connect_to_broker(const char *socket_path);
int  get_user_info(pam_handle_t *pamh,
                   const char **username,
                   const char **service,
                   const char **rhost,
                   const char **tty);
int  send_auth_request(int sock,
                       const char *username,
                       const char *service,
                       const char *rhost,
                       const char *tty);
int  send_check_session_request(int sock, const char *session_id);
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
