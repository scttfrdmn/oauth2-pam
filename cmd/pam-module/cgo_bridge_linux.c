/* PAM entry points for oauth2_pam.so.
 *
 * The file is named with a _linux suffix so that Go's GOOS-based file
 * selection excludes it on other platforms. A package that contains C sources
 * but compiles without cgo is rejected outright ("C source files not allowed
 * when not using cgo"), and that filtering happens while loading the package,
 * before build constraints inside the file would be consulted — so the name,
 * not a //go:build line, is what keeps `go build ./...` working on macOS.
 *
 * Protocol (see pkg/auth/broker.go for the authoritative description):
 *
 *   1. authenticate      -> status "pending" plus a user code, URL and QR code
 *   2. show the user the code, wait for them to approve at the provider
 *   3. check_session ... -> "pending" until the outcome is known, then
 *                           "authorized" / "denied" / "expired" / "error"
 *
 * Only status "authorized" grants access, and only when the local user the
 * broker resolved is the account the login was for.
 */

#include "cgo_bridge.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <json-c/json.h>

static int debug_enabled = 0;

void log_pam_message(int priority, const char *format, ...) {
    if (!debug_enabled && priority == LOG_DEBUG) return;
    va_list args;
    va_start(args, format);
    openlog(PAM_MODULE_NAME, LOG_PID, LOG_AUTHPRIV);
    vsyslog(priority, format, args);
    closelog();
    va_end(args);
}

void log_pam_message_string(int priority, const char *message) {
    if (!debug_enabled && priority == LOG_DEBUG) return;
    openlog(PAM_MODULE_NAME, LOG_PID, LOG_AUTHPRIV);
    syslog(priority, "%s", message);
    closelog();
}

/* validate_socket_path returns 0 if path is safe, -1 otherwise.
   Paths must be under /var/run/oauth2-pam/ and must not contain "..". */
int validate_socket_path(const char *path) {
    const char *required_prefix = "/var/run/oauth2-pam/";
    if (path == NULL) return -1;
    /* sun_path is 104 bytes on macOS, 108 on Linux; 103 leaves room for NUL */
    if (strlen(path) > 103) return -1;
    if (strncmp(path, required_prefix, strlen(required_prefix)) != 0) return -1;
    if (strstr(path, "..") != NULL) return -1;
    return 0;
}

int connect_to_broker(const char *socket_path) {
    int sock;
    struct sockaddr_un addr;

    log_pam_message(LOG_DEBUG, "Connecting to broker at %s", socket_path);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_pam_message(LOG_ERR, "Failed to connect to broker: %s", strerror(errno));
        close(sock);
        return -1;
    }

    log_pam_message(LOG_DEBUG, "Connected to broker");
    return sock;
}

int get_user_info(pam_handle_t *pamh, const char **username, const char **service,
                  const char **rhost, const char **tty) {
    int retval;

    retval = pam_get_user(pamh, username, NULL);
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if (*username == NULL || **username == '\0') {
        log_pam_message(LOG_ERR, "Empty username from PAM");
        return PAM_USER_UNKNOWN;
    }

    if (pam_get_item(pamh, PAM_SERVICE, (const void**)service) != PAM_SUCCESS || *service == NULL)
        *service = "unknown";
    if (pam_get_item(pamh, PAM_RHOST,   (const void**)rhost)   != PAM_SUCCESS || *rhost == NULL)
        *rhost = "localhost";
    if (pam_get_item(pamh, PAM_TTY,     (const void**)tty)     != PAM_SUCCESS || *tty == NULL)
        *tty = "unknown";

    log_pam_message(LOG_DEBUG, "user=%s service=%s rhost=%s tty=%s",
                    *username, *service, *rhost, *tty);
    return PAM_SUCCESS;
}

/* send_json sends a serialized request and reports whether the whole thing
   went out. json-c does the escaping, so no field needs sanitizing here. */
static int send_json(int sock, json_object *req) {
    const char *req_str = json_object_to_json_string(req);
    size_t req_len = strlen(req_str);

    log_pam_message(LOG_DEBUG, "Sending request: %s", req_str);

    ssize_t sent = send(sock, req_str, req_len, 0);
    if (sent == -1 || (size_t)sent != req_len) {
        log_pam_message(LOG_ERR, "Failed to send request: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int send_auth_request(int sock, const char *username, const char *service,
                      const char *rhost, const char *tty) {
    json_object *req      = json_object_new_object();
    json_object *metadata = json_object_new_object();
    const char *login_type = "ssh";

    /* login_type must be one of the values the broker's validateRequest
       accepts ("ssh", "console", "gui"); anything else is rejected outright. */
    if (strcmp(service, "sshd") == 0)
        login_type = "ssh";
    else if (strstr(tty, "tty") != NULL)
        login_type = "console";
    else if (strstr(service, "gdm") != NULL || strstr(service, "lightdm") != NULL)
        login_type = "gui";

    char pid_str[24];
    snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
    json_object_object_add(metadata, "service", json_object_new_string(service));
    json_object_object_add(metadata, "tty",     json_object_new_string(tty));
    json_object_object_add(metadata, "pid",     json_object_new_string(pid_str));

    json_object_object_add(req, "type",        json_object_new_string("authenticate"));
    json_object_object_add(req, "user_id",     json_object_new_string(username));
    json_object_object_add(req, "login_type",  json_object_new_string(login_type));
    json_object_object_add(req, "target_host", json_object_new_string(rhost));
    json_object_object_add(req, "metadata",    metadata);

    int rc = send_json(sock, req);
    json_object_put(req);
    return rc;
}

int send_check_session_request(int sock, const char *session_id) {
    json_object *req = json_object_new_object();
    json_object_object_add(req, "type",       json_object_new_string("check_session"));
    json_object_object_add(req, "session_id", json_object_new_string(session_id));

    int rc = send_json(sock, req);
    json_object_put(req);
    return rc;
}

int receive_auth_response(int sock, char *response, size_t response_size) {
    size_t total = 0;
    /* Loop until the broker closes the connection (n==0) or an error occurs.
       The broker writes one JSON object then immediately closes the connection,
       so reading until EOF guarantees we have the complete response even when
       it arrives across multiple recv() calls (e.g. large device-flow payloads
       containing base64-encoded QR codes). */
    while (total < response_size - 1) {
        ssize_t n = recv(sock, response + total, response_size - 1 - total, 0);
        if (n < 0) {
            log_pam_message(LOG_ERR, "Failed to receive response: %s", strerror(errno));
            return -1;
        }
        if (n == 0) break;  /* broker closed connection — full response received */
        total += n;
    }
    if (total == 0) {
        log_pam_message(LOG_ERR, "Auth response: broker closed connection with no data");
        return -1;
    }
    if (total == response_size - 1) {
        log_pam_message(LOG_ERR, "Auth response too large (>= %zu bytes); rejecting", total);
        return -1;
    }
    response[total] = '\0';
    log_pam_message(LOG_DEBUG, "Received response (%zu bytes)", total);
    return 0;
}

int display_message(pam_handle_t *pamh, const char *message) {
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;
    int retval;

    retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (retval != PAM_SUCCESS) return retval;
    if (conv == NULL || conv->conv == NULL) return PAM_CONV_ERR;

    msg.msg_style = PAM_TEXT_INFO;
    msg.msg = message;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (resp) {
        if (resp->resp) free(resp->resp);
        free(resp);
    }
    return retval;
}

int prompt_user(pam_handle_t *pamh, const char *prompt, char *response,
                size_t response_size, int echo) {
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;
    int retval;

    if (response_size == 0) return PAM_CONV_ERR;
    response[0] = '\0';

    retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (retval != PAM_SUCCESS) return retval;
    if (conv == NULL || conv->conv == NULL) return PAM_CONV_ERR;

    msg.msg_style = echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (resp) {
        if (resp->resp) {
            if (retval == PAM_SUCCESS) {
                strncpy(response, resp->resp, response_size - 1);
                response[response_size - 1] = '\0';
            }
            /* The reply is discarded, but a user may have typed a password at
               this prompt by mistake; do not leave it on the heap. */
            memset(resp->resp, 0, strlen(resp->resp));
            free(resp->resp);
        }
        free(resp);
    }
    return retval;
}

/* copy_json_field copies a string field into a bounded buffer, leaving it as
   an empty string when the key is absent or not a string. */
static void copy_json_field(json_object *obj, const char *key,
                            char *dst, size_t dst_size) {
    json_object *field = NULL;
    dst[0] = '\0';
    if (!json_object_object_get_ex(obj, key, &field)) return;
    if (field == NULL || json_object_get_type(field) != json_type_string) return;
    const char *val = json_object_get_string(field);
    if (val == NULL) return;
    strncpy(dst, val, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

int parse_broker_response(const char *json_text, struct broker_response **out) {
    if (json_text == NULL || out == NULL) return -1;
    *out = NULL;

    json_object *root = json_tokener_parse(json_text);
    if (!root) {
        log_pam_message(LOG_ERR, "Failed to parse broker response");
        return -1;
    }
    if (json_object_get_type(root) != json_type_object) {
        log_pam_message(LOG_ERR, "Broker response is not a JSON object");
        json_object_put(root);
        return -1;
    }

    struct broker_response *r = calloc(1, sizeof(*r));
    if (r == NULL) {
        log_pam_message(LOG_ERR, "Out of memory parsing broker response");
        json_object_put(root);
        return -1;
    }

    copy_json_field(root, "status",        r->status,        sizeof(r->status));
    copy_json_field(root, "session_id",    r->session_id,    sizeof(r->session_id));
    copy_json_field(root, "user_id",       r->user_id,       sizeof(r->user_id));
    copy_json_field(root, "error_message", r->error_message, sizeof(r->error_message));
    copy_json_field(root, "instructions",  r->instructions,  sizeof(r->instructions));

    json_object *success_obj = NULL;
    if (json_object_object_get_ex(root, "success", &success_obj)) {
        r->success = json_object_get_boolean(success_obj) ? 1 : 0;
    }

    /* metadata.polling_interval is a string (the IPC metadata map is
       map[string]string), so parse it rather than reading an int. */
    json_object *meta = NULL;
    if (json_object_object_get_ex(root, "metadata", &meta) &&
        meta != NULL && json_object_get_type(meta) == json_type_object) {
        char interval[16];
        copy_json_field(meta, "polling_interval", interval, sizeof(interval));
        if (interval[0] != '\0') {
            r->poll_interval = atoi(interval);
        }
    }

    json_object_put(root);
    *out = r;
    return 0;
}

/* parse_arguments reads the module arguments from the pam.d line:
     socket=/path         broker socket (must be under /var/run/oauth2-pam/)
     poll_interval=N      seconds between check_session calls
     timeout=N            seconds to wait for the user to authorize
     debug                log at LOG_DEBUG                                  */
static void parse_arguments(int argc, const char **argv, struct module_options *opts) {
    opts->socket_path   = DEFAULT_SOCKET_PATH;
    opts->poll_interval = DEFAULT_POLL_INTERVAL;
    opts->auth_timeout  = DEFAULT_AUTH_TIMEOUT;
    opts->debug         = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            opts->debug = 1;
        } else if (strncmp(argv[i], "socket=", 7) == 0) {
            opts->socket_path = argv[i] + 7;
        } else if (strncmp(argv[i], "poll_interval=", 14) == 0) {
            int v = atoi(argv[i] + 14);
            if (v >= MIN_POLL_INTERVAL && v <= MAX_POLL_INTERVAL) opts->poll_interval = v;
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            int v = atoi(argv[i] + 8);
            if (v >= MIN_AUTH_TIMEOUT && v <= MAX_AUTH_TIMEOUT) opts->auth_timeout = v;
        }
    }
    debug_enabled = opts->debug;
}

/* monotonic_seconds is the clock the poll loop measures its deadline against.
   CLOCK_REALTIME will not do: ntpd, chronyd and `hwclock --hctosys` can step it
   at any moment, and a freshly booted or just-reconnected host — precisely where
   the first ssh login happens — is where that step is largest. A backward step
   would extend the login window past timeout=, a forward one would abandon a
   user mid-approval. CLOCK_MONOTONIC cannot be stepped. */
static long monotonic_seconds(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* Cannot happen on Linux with a valid clock id. Degrade to the realtime
           clock rather than treating the login as expired. */
        return (long)time(NULL);
    }
    return (long)ts.tv_sec;
}

/* sleep_seconds waits the full interval even if signals arrive.
   sleep() returns early on any signal and discards the unslept remainder, and
   during a keyboard-interactive exchange signals do arrive: SIGWINCH when the
   user resizes the terminal, SIGALRM from sshd's login grace timer. Each one
   would shorten a poll interval, driving more requests at the broker and at
   GitHub — whose device endpoint answers slow_down when polled too fast.
   nanosleep hands back the remaining time so the loop can finish it. */
static void sleep_seconds(long seconds) {
    struct timespec remaining;

    if (seconds <= 0) return;
    remaining.tv_sec  = (time_t)seconds;
    remaining.tv_nsec = 0;

    while (nanosleep(&remaining, &remaining) == -1 && errno == EINTR) {
        /* Interrupted by a signal; finish what is left of the interval. */
    }
}

/* broker_roundtrip opens a connection, sends one request and reads the reply.
   send_fn does the request-specific serialization. Returns 0 on success with
   *out set (caller frees), -1 on any transport or parse failure. */
static int broker_roundtrip(const struct module_options *opts,
                            int (*send_fn)(int sock, void *ctx), void *ctx,
                            struct broker_response **out) {
    char buf[MAX_RESPONSE_SIZE];
    int sock = connect_to_broker(opts->socket_path);
    if (sock == -1) return -1;

    if (send_fn(sock, ctx) != 0) {
        close(sock);
        return -1;
    }
    if (receive_auth_response(sock, buf, sizeof(buf)) != 0) {
        close(sock);
        return -1;
    }
    close(sock);

    return parse_broker_response(buf, out);
}

struct auth_ctx {
    const char *username;
    const char *service;
    const char *rhost;
    const char *tty;
};

static int send_auth_cb(int sock, void *ctx) {
    struct auth_ctx *c = (struct auth_ctx *)ctx;
    return send_auth_request(sock, c->username, c->service, c->rhost, c->tty);
}

static int send_check_cb(int sock, void *ctx) {
    return send_check_session_request(sock, (const char *)ctx);
}

/* authorized_for verifies that the broker authorized the account this login is
   for. The broker enforces the same rule before activating a session, so this
   is a second, independent check on the value we are about to act on: a reply
   that says "authorized" for a different user must never open a shell as the
   requested one. */
static int authorized_for(const struct broker_response *r, const char *username) {
    if (r->success != 1) {
        log_pam_message(LOG_ERR, "Broker reported status=authorized with success=false; refusing");
        return 0;
    }
    if (r->user_id[0] == '\0') {
        log_pam_message(LOG_ERR, "Broker authorized an empty user; refusing");
        return 0;
    }
    if (strcmp(r->user_id, username) != 0) {
        log_pam_message(LOG_ERR,
                        "Broker authorized user %s but login is for %s; refusing",
                        r->user_id, username);
        return 0;
    }
    return 1;
}

/* terminal_status_to_pam maps a terminal broker status to a PAM result.
   A decision about the user is PAM_AUTH_ERR; an operational failure is
   PAM_AUTHINFO_UNAVAIL so that a later module in the stack may still run. */
static int terminal_status_to_pam(const struct broker_response *r, const char *username) {
    if (strcmp(r->status, STATUS_DENIED) == 0) {
        log_pam_message(LOG_NOTICE, "Authentication denied for %s: %s",
                        username, r->error_message);
        return PAM_AUTH_ERR;
    }
    if (strcmp(r->status, STATUS_EXPIRED) == 0) {
        log_pam_message(LOG_NOTICE, "Authorization expired for %s: %s",
                        username, r->error_message);
        return PAM_AUTH_ERR;
    }
    if (strcmp(r->status, STATUS_ERROR) == 0) {
        log_pam_message(LOG_ERR, "Broker error authenticating %s: %s",
                        username, r->error_message);
        return PAM_AUTHINFO_UNAVAIL;
    }
    log_pam_message(LOG_ERR, "Unknown broker status '%s' for %s; failing closed",
                    r->status, username);
    return PAM_AUTH_ERR;
}

/* poll_for_authorization polls check_session until the outcome is known or the
   deadline passes. */
static int poll_for_authorization(pam_handle_t *pamh, const struct module_options *opts,
                                  const char *username, const char *session_id,
                                  int poll_interval) {
    long deadline = monotonic_seconds() + opts->auth_timeout;
    int consecutive_failures = 0;
    const int max_consecutive_failures = 3;

    (void)pamh;

    for (;;) {
        struct broker_response *r = NULL;
        if (broker_roundtrip(opts, send_check_cb, (void *)session_id, &r) != 0) {
            /* Transport hiccup or a broker restart mid-flow. Tolerate a few in
               a row — the user is waiting and a single failed connect should
               not end the login — then give up. */
            if (++consecutive_failures >= max_consecutive_failures) {
                log_pam_message(LOG_ERR,
                                "Giving up after %d consecutive check_session failures",
                                consecutive_failures);
                return PAM_AUTHINFO_UNAVAIL;
            }
        } else {
            consecutive_failures = 0;

            if (strcmp(r->status, STATUS_AUTHORIZED) == 0) {
                int ok = authorized_for(r, username);
                free(r);
                if (!ok) return PAM_AUTH_ERR;
                log_pam_message(LOG_INFO, "Authentication successful for user: %s", username);
                return PAM_SUCCESS;
            }
            if (strcmp(r->status, STATUS_PENDING) != 0) {
                int rc = terminal_status_to_pam(r, username);
                free(r);
                return rc;
            }
            free(r);
        }

        if (monotonic_seconds() + poll_interval > deadline) {
            log_pam_message(LOG_NOTICE,
                            "Timed out after %ds waiting for %s to authorize",
                            opts->auth_timeout, username);
            return PAM_AUTH_ERR;
        }
        sleep_seconds(poll_interval);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *username = NULL, *service = NULL, *rhost = NULL, *tty = NULL;
    struct module_options opts;
    struct broker_response *r = NULL;
    int retval;

    (void)flags;

    parse_arguments(argc, argv, &opts);

    if (validate_socket_path(opts.socket_path) != 0) {
        log_pam_message(LOG_ERR, "Invalid socket path: %s", opts.socket_path);
        return PAM_AUTHINFO_UNAVAIL;
    }

    log_pam_message(LOG_INFO, "%s v%s authentication started",
                    PAM_MODULE_NAME, PAM_MODULE_VERSION);

    retval = get_user_info(pamh, &username, &service, &rhost, &tty);
    if (retval != PAM_SUCCESS) return retval;

    log_pam_message(LOG_INFO, "Authenticating user: %s via device flow", username);

    /* Phase 1: start the device flow. */
    struct auth_ctx actx = { username, service, rhost, tty };
    if (broker_roundtrip(&opts, send_auth_cb, &actx, &r) != 0) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* A started device flow is never an authenticated user, but handle an
       "authorized" reply anyway in case a future broker can answer from a
       cached session. */
    if (strcmp(r->status, STATUS_AUTHORIZED) == 0) {
        int ok = authorized_for(r, username);
        free(r);
        return ok ? PAM_SUCCESS : PAM_AUTH_ERR;
    }

    if (strcmp(r->status, STATUS_PENDING) != 0) {
        retval = terminal_status_to_pam(r, username);
        free(r);
        return retval;
    }

    if (r->session_id[0] == '\0') {
        log_pam_message(LOG_ERR, "Broker returned status=pending with no session id");
        free(r);
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* Copy what phase 2 needs before releasing the response. */
    char session_id[MAX_SESSION_ID_LEN];
    strncpy(session_id, r->session_id, sizeof(session_id) - 1);
    session_id[sizeof(session_id) - 1] = '\0';

    int poll_interval = opts.poll_interval;
    if (r->poll_interval >= MIN_POLL_INTERVAL && r->poll_interval <= MAX_POLL_INTERVAL) {
        /* Respect the provider's requested interval; polling faster than it
           asks for earns a slow_down from the provider. */
        poll_interval = r->poll_interval;
    }

    /* Phase 2: show the code, then wait.
     *
     * The instructions go out as a prompt rather than PAM_TEXT_INFO because
     * OpenSSH buffers informational messages and may not flush them until
     * pam_sm_authenticate returns — which would show the user the code only
     * after the login had already failed. A prompt forces the text to the
     * screen and gives the user a natural way to say "I have approved".
     */
    char prompt[MAX_PROMPT_SIZE];
    const char *body = r->instructions[0] != '\0'
        ? r->instructions
        : "Device authorization required.";
    snprintf(prompt, sizeof(prompt),
             "%s\n\nPress Enter once you have approved the request: ", body);
    free(r);
    r = NULL;

    char reply[64];
    retval = prompt_user(pamh, prompt, reply, sizeof(reply), 0);
    memset(reply, 0, sizeof(reply));
    if (retval != PAM_SUCCESS) {
        log_pam_message(LOG_ERR, "Conversation failed while showing device instructions: %s",
                        pam_strerror(pamh, retval));
        return PAM_CONV_ERR;
    }

    return poll_for_authorization(pamh, &opts, username, session_id, poll_interval);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    struct module_options opts;
    (void)pamh; (void)flags;
    parse_arguments(argc, argv, &opts);
    /* No credentials to establish: the broker holds the OAuth2 token, and the
       mapper's supplementary groups are advisory (see issue #12). */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    struct module_options opts;
    (void)pamh; (void)flags;
    parse_arguments(argc, argv, &opts);
    /* Authorization was decided during authentication: the broker only issues
       an authorized status for an identity that mapped to this account. */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    struct module_options opts;
    (void)pamh; (void)flags;
    parse_arguments(argc, argv, &opts);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    struct module_options opts;
    (void)pamh; (void)flags;
    parse_arguments(argc, argv, &opts);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    struct module_options opts;
    (void)pamh; (void)flags;
    parse_arguments(argc, argv, &opts);
    /* Password changes are handled by the identity provider, not PAM */
    return PAM_AUTHTOK_ERR;
}
