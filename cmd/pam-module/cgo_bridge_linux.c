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
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/time.h>
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
 *
 * The path must sit directly under a root-owned runtime directory for the
 * broker, and must not contain "..". Both spellings of that directory are
 * accepted: /run/oauth2-pam/ is where systemd's RuntimeDirectory= creates it,
 * and /var/run/oauth2-pam/ is the traditional name for the same place — on every
 * systemd host /var/run is a symlink to /run. Accepting only the /var/run
 * spelling meant a perfectly correct socket=/run/oauth2-pam/broker.sock was
 * refused as unsafe, and the module failed closed with "Invalid socket path"
 * against a broker it could see.
 *
 * The trailing slash in each prefix is load-bearing: without it, a path under an
 * attacker-created /run/oauth2-pam-evil/ would match.
 */
int validate_socket_path(const char *path) {
    static const char *const allowed_prefixes[] = {
        "/run/oauth2-pam/",
        "/var/run/oauth2-pam/",
    };
    size_t i;
    int prefix_ok = 0;

    if (path == NULL) return -1;
    /* sun_path is 104 bytes on macOS, 108 on Linux; 103 leaves room for NUL */
    if (strlen(path) > 103) return -1;

    for (i = 0; i < sizeof(allowed_prefixes) / sizeof(allowed_prefixes[0]); i++) {
        if (strncmp(path, allowed_prefixes[i], strlen(allowed_prefixes[i])) == 0) {
            prefix_ok = 1;
            break;
        }
    }
    if (!prefix_ok) return -1;
    if (strstr(path, "..") != NULL) return -1;
    return 0;
}

/* set_io_timeout bounds every send and receive on sock.
 *
 * SO_SNDTIMEO also bounds connect() on a blocking Linux socket, which matters
 * when the broker's listen backlog is full: without it connect() waits
 * indefinitely for a slot. */
static int set_io_timeout(int sock, int seconds) {
    struct timeval tv;

    tv.tv_sec  = seconds;
    tv.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1 ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        log_pam_message(LOG_ERR, "Failed to set socket timeout: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* transfer_deadline and apply_remaining bound a whole request or reply, not each
   syscall.
 *
 * SO_RCVTIMEO and SO_SNDTIMEO expire per recv() and per send() call, which bounds
 * a peer that says nothing but not a peer that says one byte just inside every
 * timeout: that peer extends the wait per byte, without limit. "A deadline on
 * every receive" is then satisfied per syscall while the thing it was for — a
 * wedged or hostile broker cannot hang a login — is defeated. The module's own
 * timeout= does not help either; it is only consulted between polls, and does not
 * start counting until after the PAM conversation.
 *
 * So the deadline is taken once, before the first syscall, and the socket's
 * timeout is shrunk to whatever is left of it before each one. The budget is the
 * timeout connect_to_broker already put on the socket — see AUTH_IO_TIMEOUT and
 * POLL_IO_TIMEOUT — read back rather than passed in, so that no caller can bound
 * a transfer differently from the connection it runs on. The shrunk value is left
 * on the socket, which is fine because broker_roundtrip closes it after one
 * request and one reply.
 *
 * CLOCK_MONOTONIC for the reason monotonic_seconds gives below: a clock that can
 * be stepped would either extend the wait or abandon a transfer in progress.
 *
 * transfer_deadline returns -1 when there is no budget to enforce — no timeout on
 * the socket, or no usable clock — and the caller then keeps the per-call bound it
 * already had rather than refusing to talk. */
static int transfer_deadline(int sock, int optname, struct timespec *deadline) {
    struct timeval tv;
    socklen_t len = sizeof(tv);

    if (getsockopt(sock, SOL_SOCKET, optname, &tv, &len) != 0) return -1;
    if (tv.tv_sec <= 0 && tv.tv_usec <= 0) return -1;
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) return -1;

    deadline->tv_sec  += tv.tv_sec;
    deadline->tv_nsec += (long)tv.tv_usec * 1000;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
    return 0;
}

/* apply_remaining shrinks the socket's timeout to the time left before the
   deadline. It returns -1 once the deadline has passed, which is the caller's
   signal to give up rather than start another syscall. */
static int apply_remaining(int sock, int optname, const struct timespec *deadline) {
    struct timespec now;
    struct timeval tv;
    long remaining_ms;

    /* A clock that has stopped working mid-transfer cannot say how much of the
       budget is left. Proceed on the timeout already set — the per-call bound the
       module had before this existed — rather than fail a login in progress over a
       condition that cannot happen on Linux with a valid clock id. */
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;

    remaining_ms = (long)(deadline->tv_sec - now.tv_sec) * 1000 +
                   (deadline->tv_nsec - now.tv_nsec) / 1000000L;
    if (remaining_ms <= 0) return -1;

    tv.tv_sec  = (time_t)(remaining_ms / 1000);
    tv.tv_usec = (suseconds_t)(remaining_ms % 1000) * 1000;
    /* A zero timeval means "no timeout at all" to setsockopt, so the last
       fraction of a millisecond must never round down into one. */
    if (tv.tv_sec == 0 && tv.tv_usec == 0) tv.tv_usec = 1000;

    if (setsockopt(sock, SOL_SOCKET, optname, &tv, sizeof(tv)) != 0) {
        log_pam_message(LOG_ERR, "Failed to shrink socket timeout: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int connect_to_broker(const char *socket_path, int io_timeout) {
    int sock;
    struct sockaddr_un addr;

    log_pam_message(LOG_DEBUG, "Connecting to broker at %s (io timeout %ds)",
                    socket_path, io_timeout);

    if (io_timeout <= 0) {
        log_pam_message(LOG_ERR, "Refusing to connect without an I/O timeout");
        return -1;
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        log_pam_message(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    /* Before connect(), so the timeout covers it too. */
    if (set_io_timeout(sock, io_timeout) != 0) {
        close(sock);
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
    if (pam_get_item(pamh, PAM_TTY,     (const void**)tty)     != PAM_SUCCESS || *tty == NULL)
        *tty = "unknown";

    /* Empty, not "localhost", when PAM_RHOST is unset. A console or cron login
       has no remote host, and substituting "localhost" put a fabricated origin
       into the audit record — the one field an investigator reads to answer
       "where did this login come from". */
    if (pam_get_item(pamh, PAM_RHOST,   (const void**)rhost)   != PAM_SUCCESS || *rhost == NULL)
        *rhost = "";

    log_pam_message(LOG_DEBUG, "user=%s service=%s rhost=%s tty=%s",
                    *username, *service, *rhost, *tty);
    return PAM_SUCCESS;
}

/* send_json sends a serialized request and reports whether the whole thing
   went out. json-c does the escaping, so no field needs sanitizing here.

   MSG_NOSIGNAL is not optional here. If the broker has closed its end — it was
   restarted, or it hung up on a request it refused — a plain send() raises
   SIGPIPE, whose default disposition terminates the process. That process is
   sshd's pre-auth child, so a broker restart mid-login would kill the connection
   outright instead of failing the module. A PAM module cannot fix this by
   installing a handler: the signal disposition belongs to the host application,
   and quietly changing it would leak out of the module for the life of the
   process. Suppressing the signal per call is the only correct scope.

   The loop exists because a short send is legal on a stream socket. The old code
   treated one as a failure, which is at least fail-closed, but a partial request
   also leaves the broker parsing a truncated JSON object. A peer that accepts one
   byte per timeout would otherwise keep the loop going indefinitely, so the whole
   request is bounded by one deadline — see transfer_deadline. */
static int send_json(int sock, json_object *req) {
    const char *req_str = json_object_to_json_string(req);
    size_t req_len = strlen(req_str);
    size_t total = 0;
    struct timespec deadline;
    int bounded = transfer_deadline(sock, SO_SNDTIMEO, &deadline) == 0;

    log_pam_message(LOG_DEBUG, "Sending request: %s", req_str);

    while (total < req_len) {
        if (bounded && apply_remaining(sock, SO_SNDTIMEO, &deadline) != 0) {
            log_pam_message(LOG_ERR,
                            "Request deadline elapsed after sending %zu of %zu bytes",
                            total, req_len);
            return -1;
        }
        ssize_t sent = send(sock, req_str + total, req_len - total, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (sent == -1 && errno == EINTR) continue;
            log_pam_message(LOG_ERR, "Failed to send request after %zu of %zu bytes: %s",
                            total, req_len, strerror(errno));
            return -1;
        }
        total += (size_t)sent;
    }
    return 0;
}

/* valid_zone_id reports whether s is a plausible IPv6 zone: an interface name or
   a numeric scope id, as sshd's getnameinfo() appends it.
 *
 * Checked by charset rather than with if_nametoindex, deliberately. The zone
 * names an interface, and whether this host can resolve that name is not the
 * question being asked: an audit field that appears or disappears depending on the
 * interface list is worse than one that reports what the peer said. The charset is
 * what keeps the value safe to put on the wire — it is the only part of rhost that
 * inet_pton is not vetting. */
static int valid_zone_id(const char *s) {
    size_t i;

    if (s[0] == '\0') return 0;
    /* IFNAMSIZ - 1. Anything longer is not an interface name, and a numeric scope
       id is far shorter. */
    if (strlen(s) > 15) return 0;

    for (i = 0; s[i] != '\0'; i++) {
        if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_' && s[i] != '.')
            return 0;
    }
    return 1;
}

/* copy_source_ip fills dst with rhost when rhost is an IP address literal, and
   with an empty string otherwise.
 *
 * PAM_RHOST is an address only when sshd was not asked to resolve it; with
 * `UseDNS yes` it is a hostname, and a fully qualified one can exceed the 45
 * bytes the broker allows for source_ip — which would make it reject the entire
 * request and fail the login. So the field carries an address or nothing, and the
 * raw value travels in metadata.rhost either way.
 *
 * The %zone suffix is split off before validating, because inet_pton fails on a
 * zoned literal: inet_pton(AF_INET6, "fe80::1%eth0", …) returns 0, so a
 * link-local login was audited as origin-unknown rather than from the address it
 * came from. docs/wire-protocol.md conformance item 8 names that exact address —
 * "a validator that rejects fe80::1%eth0 refuses a login this contract sized a
 * field for" — and per the source_ip rules in the same section, unknown must never
 * satisfy a network requirement, so dropping the field silently degrades any
 * policy that comes to depend on it.
 *
 * The whole string, zone included, goes on the wire: the zone is which interface
 * the peer is on, which is not redundant with a link-local address — the same
 * fe80:: address can be a different host on a different link. Only IPv6 takes a
 * zone; a '%' in an IPv4 literal or a hostname is not a scope, so those are
 * refused as before. */
static void copy_source_ip(const char *rhost, char *dst, size_t dst_size) {
    unsigned char v4[4];
    unsigned char v6[16];
    char addr[MAX_SOURCE_IP_LEN];
    const char *zone;
    size_t addr_len;

    dst[0] = '\0';
    if (rhost == NULL || rhost[0] == '\0') return;
    if (strlen(rhost) >= dst_size) return;

    zone = strchr(rhost, '%');
    addr_len = zone != NULL ? (size_t)(zone - rhost) : strlen(rhost);
    if (addr_len == 0 || addr_len >= sizeof(addr)) return;
    memcpy(addr, rhost, addr_len);
    addr[addr_len] = '\0';

    if (zone != NULL) {
        if (!valid_zone_id(zone + 1)) return;
        if (inet_pton(AF_INET6, addr, v6) != 1) return;
    } else if (inet_pton(AF_INET, addr, v4) != 1 && inet_pton(AF_INET6, addr, v6) != 1) {
        return;
    }

    strncpy(dst, rhost, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

/* copy_target_host fills dst with this host's name — the host being logged into,
   which is what target_host means. The module used to send PAM_RHOST here, so
   every audit record named the *client* as the target and left source_ip empty:
   both fields were populated, and both were wrong. */
static void copy_target_host(char *dst, size_t dst_size) {
    dst[0] = '\0';
    if (gethostname(dst, dst_size) != 0) {
        /* Not fatal. An unnamed host is a worse audit record, not a reason to
           refuse a login. */
        log_pam_message(LOG_WARNING, "gethostname failed: %s", strerror(errno));
        dst[0] = '\0';
        return;
    }
    /* POSIX allows truncation without a NUL when the name does not fit. */
    dst[dst_size - 1] = '\0';
}

int send_auth_request(int sock, const char *username, const char *service,
                      const char *rhost, const char *tty, const char *provider) {
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
    /* The unabridged PAM_RHOST, whether or not it is an address; source_ip below
       takes it only when it is one. */
    json_object_object_add(metadata, "rhost",   json_object_new_string(rhost ? rhost : ""));

    char source_ip[MAX_SOURCE_IP_LEN];
    char target_host[MAX_HOSTNAME_LEN];
    copy_source_ip(rhost, source_ip, sizeof(source_ip));
    copy_target_host(target_host, sizeof(target_host));

    json_object_object_add(req, "protocol_version", json_object_new_int(PROTOCOL_VERSION));
    json_object_object_add(req, "type",        json_object_new_string("authenticate"));
    json_object_object_add(req, "user_id",     json_object_new_string(username));
    json_object_object_add(req, "login_type",  json_object_new_string(login_type));
    json_object_object_add(req, "source_ip",   json_object_new_string(source_ip));
    json_object_object_add(req, "target_host", json_object_new_string(target_host));
    json_object_object_add(req, "metadata",    metadata);
    /* Omitted rather than sent empty when no provider= argument is given: the
       broker reads an absent field as "your default", and an empty string means
       the same, but omitting it keeps the request identical to what an older
       module sends. */
    if (provider != NULL && provider[0] != '\0')
        json_object_object_add(req, "provider", json_object_new_string(provider));

    int rc = send_json(sock, req);
    json_object_put(req);
    return rc;
}

int send_check_session_request(int sock, const char *session_id) {
    json_object *req = json_object_new_object();
    json_object_object_add(req, "protocol_version", json_object_new_int(PROTOCOL_VERSION));
    json_object_object_add(req, "type",       json_object_new_string("check_session"));
    json_object_object_add(req, "session_id", json_object_new_string(session_id));

    int rc = send_json(sock, req);
    json_object_put(req);
    return rc;
}

int receive_auth_response(int sock, char *response, size_t response_size) {
    size_t total = 0;
    int filled = 0;
    struct timespec deadline;
    int bounded;

    if (response == NULL || response_size < 2) return -1;

    /* One deadline for the whole reply, not one per recv(). Without it the only
       bound is SO_RCVTIMEO, which a peer sending a byte just inside every timeout
       extends per byte: a 16 KB reply drip-fed at that rate holds the login open
       for hours, and holds an sshd pre-auth child with it. See
       transfer_deadline. */
    bounded = transfer_deadline(sock, SO_RCVTIMEO, &deadline) == 0;

    /* Loop until the broker closes the connection (n==0) or an error occurs.
       The broker writes one JSON object then immediately closes the connection,
       so reading until EOF guarantees we have the complete response even when
       it arrives across multiple recv() calls (e.g. large device-flow payloads
       containing base64-encoded QR codes). */
    while (total < response_size - 1) {
        if (bounded && apply_remaining(sock, SO_RCVTIMEO, &deadline) != 0) {
            log_pam_message(LOG_ERR,
                            "Broker still sending after the reply deadline; got %zu bytes, rejecting",
                            total);
            return -1;
        }
        ssize_t n = recv(sock, response + total, response_size - 1 - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* SO_RCVTIMEO elapsed: the broker accepted the connection and
                   then stopped talking. Fail closed rather than wait for sshd's
                   LoginGraceTime to kill the session. */
                log_pam_message(LOG_ERR,
                                "Broker stopped responding after %zu bytes; timed out", total);
                return -1;
            }
            log_pam_message(LOG_ERR, "Failed to receive response: %s", strerror(errno));
            return -1;
        }
        if (n == 0) goto done;  /* broker closed connection — full response received */
        total += (size_t)n;
    }

    /* The buffer is full but no EOF has been seen, so the response is either
       exactly response_size - 1 bytes long or longer than we accept. One more
       read answers which — without it, a complete response that happens to be
       exactly this length was rejected as too large. */
    filled = 1;
    for (;;) {
        char extra;
        if (bounded && apply_remaining(sock, SO_RCVTIMEO, &deadline) != 0) {
            log_pam_message(LOG_ERR,
                            "Reply deadline elapsed with the buffer full; rejecting");
            return -1;
        }
        ssize_t n = recv(sock, &extra, 1, 0);
        if (n > 0) {
            log_pam_message(LOG_ERR,
                            "Auth response larger than the %zu bytes we accept; rejecting",
                            response_size - 1);
            return -1;
        }
        if (n == 0) break;  /* exactly response_size - 1 bytes, and complete */
        if (errno == EINTR) continue;
        /* Neither more data nor a clean close: we cannot tell whether what we
           hold is the whole response, so do not act on it. */
        log_pam_message(LOG_ERR,
                        "Broker neither closed nor continued after %zu bytes; rejecting",
                        total);
        return -1;
    }

done:
    if (total == 0) {
        log_pam_message(LOG_ERR, "Auth response: broker closed connection with no data");
        return -1;
    }
    response[total] = '\0';
    log_pam_message(LOG_DEBUG, "Received response (%zu bytes%s)", total,
                    filled ? ", at the size limit" : "");
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

/* copy_json_block copies a pre-rendered multi-line field, and drops it rather than
   truncating it when it does not fit.
 *
 * The difference from copy_json_field matters for exactly one field, qr_code. The
 * others are values — a status, a user id, a message — where a truncated copy is
 * still a usable, if damaged, version of what was sent. Block art is not: half a QR
 * symbol cannot be scanned, and it renders as a broken box that reads like a bug in
 * the module rather than like "there is no QR code here". Since an absent qr_code is
 * an ordinary reply the prompt already handles (the broker sends none above a
 * 200-byte verification_uri), dropping an oversized one lands on a case that is
 * already correct.
 *
 * The bound is the module's own. The broker sanitizes this field with
 * SanitizePromptBlock before it goes on the wire, so escaping is not re-implemented
 * here — but "someone else bounded it" is not a bound on the buffer this copies
 * into. */
static void copy_json_block(json_object *obj, const char *key,
                            char *dst, size_t dst_size) {
    json_object *field = NULL;
    dst[0] = '\0';
    if (!json_object_object_get_ex(obj, key, &field)) return;
    if (field == NULL || json_object_get_type(field) != json_type_string) return;
    const char *val = json_object_get_string(field);
    if (val == NULL) return;
    size_t len = strlen(val);
    if (len >= dst_size) {
        log_pam_message(LOG_WARNING,
                        "Broker sent a %zu-byte %s; this module renders at most %zu, dropping it",
                        len, key, dst_size - 1);
        return;
    }
    memcpy(dst, val, len + 1);
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
    copy_json_field(root, "error_code",    r->error_code,    sizeof(r->error_code));
    copy_json_field(root, "error_message", r->error_message, sizeof(r->error_message));
    copy_json_field(root, "instructions",  r->instructions,  sizeof(r->instructions));
    copy_json_block(root, "qr_code",       r->qr_code,       sizeof(r->qr_code));

    /* success is read strictly, because json_object_get_boolean *coerces*: any
       non-empty string and any non-zero number read as true, so "success":"false"
       would arrive here as success = 1. That is a fail-open read of one of the two
       conjuncts authorized_for requires — the module would grant a login off a
       reply that spelled out the opposite.
     *
     * Go's encoding/json cannot emit that shape, so this broker never will. The
     * module is specified to be independently defensible against a broker that is
     * "an older version of itself", though, and that is the whole reason the check
     * exists twice; a wrong type for this field is a malformed reply, and a
     * malformed reply is a transport failure rather than a decision about the
     * user. Same treatment as protocol_version below. */
    json_object *success_obj = NULL;
    if (json_object_object_get_ex(root, "success", &success_obj)) {
        if (success_obj == NULL || json_object_get_type(success_obj) != json_type_boolean) {
            log_pam_message(LOG_ERR,
                            "Broker sent a non-boolean \"success\"; rejecting the reply");
            free(r);
            json_object_put(root);
            return -1;
        }
        r->success = json_object_get_boolean(success_obj) ? 1 : 0;
    }

    /* Absent means 1: a v0.2.x broker predates the field. Recorded rather than
       acted on here, so the one place that decides what to do with it is the
       caller — see check_protocol_version. */
    json_object *pv_obj = NULL;
    if (json_object_object_get_ex(root, "protocol_version", &pv_obj) &&
        pv_obj != NULL && json_object_get_type(pv_obj) == json_type_int) {
        r->protocol_version = json_object_get_int(pv_obj);
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
     provider=name        which configured provider to authenticate against;
                          omit for the broker's default (first configured)
     poll_interval=N      seconds between check_session calls
     timeout=N            seconds to wait for the user to authorize
     debug                log at LOG_DEBUG                                  */
static void parse_arguments(int argc, const char **argv, struct module_options *opts) {
    opts->socket_path   = DEFAULT_SOCKET_PATH;
    opts->provider      = NULL;
    opts->poll_interval = DEFAULT_POLL_INTERVAL;
    opts->auth_timeout  = DEFAULT_AUTH_TIMEOUT;
    opts->debug         = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            opts->debug = 1;
        } else if (strncmp(argv[i], "socket=", 7) == 0) {
            opts->socket_path = argv[i] + 7;
        } else if (strncmp(argv[i], "provider=", 9) == 0) {
            opts->provider = argv[i] + 9;
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

/* The two fixed pieces of the device-flow prompt.
 *
 * PROMPT_TRAILER is why the instructions are shown as a prompt rather than as
 * PAM_TEXT_INFO — see the call site. QR_PROMPT_HEADER is the line that used to sit
 * above the art when the broker embedded it in instructions; it is here now because
 * that is where the art is rendered from. The wording is unchanged, so the screen a
 * user sees is the one they saw before #56.
 */
#define QR_PROMPT_HEADER "Scan QR code with your phone:"
#define PROMPT_TRAILER   "Press Enter once you have approved the request: "

/* build_device_prompt renders what the user sees: the broker's instructions, the
   QR art when the reply carried any, and the trailer that says what to do next.
 *
 * The art is a field of its own on the wire and is not inside instructions — #56
 * removed it from there because serializing it twice let a hostile
 * verification_uri push the reply past the 16 KiB cap. The fix left this module
 * rendering only instructions, which meant no QR code appeared at a login prompt at
 * all; this is the other half of it. The art travels once and is drawn once.
 *
 * An absent or empty qr_code is the ordinary case rather than an error — above a
 * 200-byte verification_uri the broker deliberately sends none — so it must render
 * as a prompt with no QR section in it, not as a header with nothing under it. That
 * is what the branch is for; there is nothing to fall back to and nothing to
 * apologise for, because the URL and the user code are in the instructions and those
 * are what the user acts on.
 *
 * Nothing is escaped here. The art is sanitized with SanitizePromptBlock before it
 * goes on the wire (pkg/auth/broker.go), and a second, different filter in the
 * consumer is how two implementations of one policy come to disagree. What this
 * module owes is a bound on what it copies, and that is copy_json_block's job at
 * parse time — by the time the field is read here it is already known to fit. */
static void build_device_prompt(char *prompt, size_t prompt_size,
                                const struct broker_response *r) {
    const char *body = r->instructions[0] != '\0'
        ? r->instructions
        : "Device authorization required.";

    if (r->qr_code[0] != '\0') {
        snprintf(prompt, prompt_size, "%s\n%s\n%s\n%s",
                 body, QR_PROMPT_HEADER, r->qr_code, PROMPT_TRAILER);
        return;
    }
    snprintf(prompt, prompt_size, "%s\n\n%s", body, PROMPT_TRAILER);
}

/* protocol_version_supported reports whether a reply is written in a contract
   this module implements. Absent (0) means version 1: a v0.2.x broker predates
   the field, and refusing it would break an upgrade in the direction nobody
   upgrades — the broker and the module are installed from the same archive, but
   an administrator may well restart one before the other.

   A version this module does not know is a transport failure rather than a
   decision about the user. The danger is not that the reply fails to parse; it is
   that it parses fine and "authorized" means something new. Reading it under the
   wrong contract is the one outcome worth ruling out.

   See docs/wire-protocol.md. */
static int protocol_version_supported(const struct broker_response *r) {
    if (r == NULL) return 0;
    return r->protocol_version == 0 || r->protocol_version == PROTOCOL_VERSION;
}

/* broker_roundtrip opens a connection, sends one request and reads the reply.
   send_fn does the request-specific serialization. io_timeout bounds every
   operation on the socket; see AUTH_IO_TIMEOUT and POLL_IO_TIMEOUT for why the
   two phases differ. Returns 0 on success with *out set (caller frees), -1 on
   any transport or parse failure. */
static int broker_roundtrip(const struct module_options *opts, int io_timeout,
                            int (*send_fn)(int sock, void *ctx), void *ctx,
                            struct broker_response **out) {
    char buf[RESPONSE_BUF_SIZE];
    int sock = connect_to_broker(opts->socket_path, io_timeout);
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

    if (parse_broker_response(buf, out) != 0) return -1;

    /* Checked here so every reply goes through it — no path reads a response
       without coming through this function. */
    if (!protocol_version_supported(*out)) {
        log_pam_message(LOG_ERR,
                        "Broker speaks protocol version %d, this module speaks %d; refusing",
                        (*out)->protocol_version, PROTOCOL_VERSION);
        free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}

struct auth_ctx {
    const char *username;
    const char *service;
    const char *rhost;
    const char *tty;
    const char *provider;
};

static int send_auth_cb(int sock, void *ctx) {
    struct auth_ctx *c = (struct auth_ctx *)ctx;
    return send_auth_request(sock, c->username, c->service, c->rhost, c->tty, c->provider);
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

/* is_rate_limited reports whether a reply is the broker asking to slow down
   rather than answering. It arrives as status "error" with error_code
   RATE_LIMITED, which is indistinguishable from a real failure unless the code is
   read — and reading it is part of the wire contract (see
   internal/ipc.ErrorCodeRateLimited). Treating it as terminal failed logins that
   were only being throttled. */
static int is_rate_limited(const struct broker_response *r) {
    return strcmp(r->error_code, ERROR_CODE_RATE_LIMITED) == 0;
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
        /* Capacity conditions are not decisions about the user, and an operator
           reading the log needs to be able to tell them apart from a broker that
           is broken. Both already map to PAM_AUTHINFO_UNAVAIL — "ask someone
           else, or try again" — which is the right answer for a host that is
           merely busy. Neither is retried here: the rate limiter's window is a
           fixed minute, and the concurrency cap is held by other logins for as
           long as their device flows live, so a retry inside this login would
           just spend the user's remaining time to fail again. */
        if (is_rate_limited(r)) {
            log_pam_message(LOG_WARNING,
                            "Broker rate-limited the authenticate request for %s; "
                            "the host's per-caller budget is exhausted", username);
            return PAM_AUTHINFO_UNAVAIL;
        }
        if (strcmp(r->error_code, "AUTH_LIMIT_REACHED") == 0) {
            log_pam_message(LOG_WARNING,
                            "Too many device flows already in progress on this host; "
                            "refusing %s (max_concurrent_auths)", username);
            return PAM_AUTHINFO_UNAVAIL;
        }
        /* The other capacity refusal, and the one that names a limit the operator
           set per user rather than per host — so it needs a message of its own or
           "logins are being refused" has two indistinguishable causes. It reached
           this branch only after issue #84: the broker used to send it as
           status "denied", which lands on the PAM_AUTH_ERR branch above and tells
           the user their credentials were wrong when the truth is that they are
           already logged in elsewhere. Both capacity codes are status "error" now,
           so both answer PAM_AUTHINFO_UNAVAIL. */
        if (strcmp(r->error_code, "SESSION_LIMIT_REACHED") == 0) {
            log_pam_message(LOG_WARNING,
                            "%s already holds the maximum number of active sessions; "
                            "refusing this one (max_concurrent_sessions)", username);
            return PAM_AUTHINFO_UNAVAIL;
        }
        log_pam_message(LOG_ERR, "Broker error authenticating %s: %s (%s)",
                        username, r->error_message, r->error_code);
        return PAM_AUTHINFO_UNAVAIL;
    }
    log_pam_message(LOG_ERR, "Unknown broker status '%s' for %s; failing closed",
                    r->status, username);
    return PAM_AUTH_ERR;
}

/* free_session_data is the cleanup PAM runs when it destroys the handle this
   session id was filed under. Without it the strdup below leaks once per login in
   a long-lived sshd, and the id — which names a live session at the broker —
   stays in freed heap for whatever allocates next to read. */
static void free_session_data(pam_handle_t *pamh, void *data, int error_status) {
    (void)pamh; (void)error_status;
    if (data == NULL) return;
    memset(data, 0, strlen((char *)data));
    free(data);
}

/* remember_session_id files the authenticated session id with PAM so that
   pam_sm_acct_mgmt can re-check the same session the auth stage established.

   pam_set_data and not a file-static variable, which is the shortcut and is wrong
   in two ways. The .so is loaded once into a process that handles many logins:
   sshd forks per connection, but a multiplexing application does not have to, and a
   static would then let one login's account stage validate against another login's
   session — with no diagnostic, because both values are real. And the account stage
   may run in a process that never ran the auth stage at all (su, cron, an sshd
   built differently), where a static holds whatever the last caller left behind or
   nothing at all. The PAM handle is the thing whose lifetime actually matches "this
   login", which is why PAM offers this at all.

   Failure to store is logged and otherwise ignored: it makes the account stage see
   no session and answer PAM_IGNORE, which is the closed direction. */
static void remember_session_id(pam_handle_t *pamh, const char *session_id) {
    char *copy;
    int rc;

    if (session_id == NULL || session_id[0] == '\0') return;

    copy = strdup(session_id);
    if (copy == NULL) {
        log_pam_message(LOG_WARNING,
                        "Out of memory storing the session id; the account stage "
                        "will have nothing to re-check");
        return;
    }
    rc = pam_set_data(pamh, SESSION_DATA_KEY, copy, free_session_data);
    if (rc != PAM_SUCCESS) {
        log_pam_message(LOG_WARNING, "pam_set_data(%s) failed: %s",
                        SESSION_DATA_KEY, pam_strerror(pamh, rc));
        /* PAM took no ownership, so this side still owns it. */
        free(copy);
    }
}

/* account_status_to_pam maps a check_session reply to an account-management
   result. It is the account stage's whole decision and is deliberately not
   terminal_status_to_pam: the two stages answer different questions and PAM
   distinguishes their return codes. Authentication answers "is this the user",
   whose refusal is PAM_AUTH_ERR; account management answers "may this user log in
   now", whose refusal is PAM_PERM_DENIED. Returning PAM_AUTH_ERR here would tell
   sshd the password was wrong, and it would offer a retry for a session that has
   been revoked.

   Every branch that is not "authorized, for this user" denies. There is no status
   worth treating as probably fine: this runs after authentication succeeded, so
   the only reason to re-ask is that the answer may have changed, and an answer
   that cannot be read is not an answer that says yes. */
static int account_status_to_pam(const struct broker_response *r, const char *username) {
    if (strcmp(r->status, STATUS_AUTHORIZED) == 0) {
        /* Same check the auth stage makes, called rather than restated: a second
           spelling of "does the returned user match" is a second thing that can be
           weakened on its own, and this one guards the stage that runs after the
           password prompt is over. */
        if (authorized_for(r, username)) {
            log_pam_message(LOG_DEBUG, "Account check passed for %s", username);
            return PAM_SUCCESS;
        }
        log_pam_message(LOG_ERR,
                        "Broker still reports an authorized session, but not for %s; "
                        "denying the account stage", username);
        return PAM_PERM_DENIED;
    }

    /* "error" splits, and the split is the same one the auth stage makes: some
       error codes mean the broker declined to answer rather than answered "no".
       RATE_LIMITED is the limiter's window, RESPONSE_TOO_LARGE is a reply that did
       not fit the cap — in both the module has no information, so it says so and
       lets the rest of the stack decide, instead of denying a login on the strength
       of a message that was never about the user.

       SESSION_NOT_FOUND is *not* in this class, even though it is also an "error":
       a session the broker has forgotten, revoked or expired out of its store is
       precisely the case issue #75 is about, and "I have no record of this" has to
       deny. */
    if (strcmp(r->status, STATUS_ERROR) == 0 &&
        (is_rate_limited(r) ||
         strcmp(r->error_code, ERROR_CODE_RESPONSE_TOO_LARGE) == 0)) {
        log_pam_message(LOG_WARNING,
                        "Broker could not answer the account check for %s (%s); "
                        "reporting the session as unverifiable", username, r->error_code);
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* denied, expired, error/SESSION_NOT_FOUND, a pending session that should not
       be pending after a successful authentication, and any status this module has
       never heard of. */
    log_pam_message(LOG_NOTICE,
                    "Account check for %s refused: broker reports status=%s (%s: %s)",
                    username, r->status, r->error_code, r->error_message);
    return PAM_PERM_DENIED;
}

/* account_decision is pam_sm_acct_mgmt with the PAM handle taken out, so that the
   test suite can drive every branch: pam_set_data and pam_get_data refuse to run
   outside a service module (they check __PAM_FROM_APP), so a test cannot build a
   handle carrying session data and ask the real entry point.

   session_id NULL or empty means this module did not authenticate this login. */
static int account_decision(const struct module_options *opts, const char *username,
                            const char *session_id) {
    struct broker_response *r = NULL;
    int rc;

    if (session_id == NULL || session_id[0] == '\0') {
        /* PAM_IGNORE: "this is not my business", the one honest answer when the
           module has no session of its own to check. Not PAM_SUCCESS — approving a
           login this module knows nothing about is fail-open, and it would make
           `account required oauth2_pam.so` silently approve every account on the
           host, including logins that never went near a device flow. PAM_IGNORE is
           also safe in a stack of one: Linux-PAM turns an all-PAM_IGNORE account
           stack into PAM_PERM_DENIED rather than success. */
        log_pam_message(LOG_DEBUG,
                        "No session of this module's for %s; leaving the account "
                        "decision to the rest of the stack", username);
        return PAM_IGNORE;
    }

    if (broker_roundtrip(opts, POLL_IO_TIMEOUT, send_check_cb,
                         (void *)session_id, &r) != 0) {
        /* Unreachable broker, a connection that dies mid-reply, a reply that is
           not JSON, a reply over the cap, a protocol version this module cannot
           read: broker_roundtrip has already logged which. None of them is a
           statement about the user, so none of them is a denial. */
        log_pam_message(LOG_ERR,
                        "Could not re-check the session for %s at the account stage",
                        username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    rc = account_status_to_pam(r, username);
    free(r);
    return rc;
}

/* poll_for_authorization polls check_session until the outcome is known or the
   deadline passes. */
static int poll_for_authorization(pam_handle_t *pamh, const struct module_options *opts,
                                  const char *username, const char *session_id,
                                  int poll_interval) {
    long deadline = monotonic_seconds() + opts->auth_timeout;
    int consecutive_failures = 0;
    const int max_consecutive_failures = 3;
    /* Grows only while the broker is throttling us, and resets as soon as it
       answers again. */
    int backoff = poll_interval;

    for (;;) {
        int wait = poll_interval;
        struct broker_response *r = NULL;

        if (broker_roundtrip(opts, POLL_IO_TIMEOUT, send_check_cb, (void *)session_id, &r) != 0) {
            /* Transport hiccup or a broker restart mid-flow. Tolerate a few in
               a row — the user is waiting and a single failed connect should
               not end the login — then give up. */
            if (++consecutive_failures >= max_consecutive_failures) {
                log_pam_message(LOG_ERR,
                                "Giving up after %d consecutive check_session failures",
                                consecutive_failures);
                return PAM_AUTHINFO_UNAVAIL;
            }
        } else if (is_rate_limited(r)) {
            /* Not a failure and not an answer: the broker is asking for a slower
               poll. Back off geometrically instead of hammering the same closed
               window, and do not spend the transport-failure budget on it — three
               tries at the normal interval would be over in fifteen seconds, well
               inside the limiter's one-minute window, and the login would die for
               a condition that clears on its own. The deadline below is what
               bounds this; a throttled poll costs the broker nothing. */
            backoff *= 2;
            if (backoff > MAX_POLL_INTERVAL) backoff = MAX_POLL_INTERVAL;
            wait = backoff;
            log_pam_message(LOG_WARNING,
                            "Broker rate-limited a session poll for %s; retrying in %ds",
                            username, wait);
            free(r);
            r = NULL;
        } else {
            consecutive_failures = 0;
            backoff = poll_interval;

            if (strcmp(r->status, STATUS_AUTHORIZED) == 0) {
                int ok = authorized_for(r, username);
                free(r);
                if (!ok) return PAM_AUTH_ERR;
                /* Only now, with the reply verified against this login's user: the
                   account stage trusts what it finds here, so a session id stored
                   before the check would hand it a session that failed one. */
                remember_session_id(pamh, session_id);
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

        if (monotonic_seconds() + wait > deadline) {
            log_pam_message(LOG_NOTICE,
                            "Timed out after %ds waiting for %s to authorize",
                            opts->auth_timeout, username);
            return PAM_AUTH_ERR;
        }
        sleep_seconds(wait);
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

    log_pam_message(LOG_INFO, "%s v%s (%s) authentication started",
                    PAM_MODULE_NAME, PAM_MODULE_VERSION, PAM_MODULE_BUILD);

    retval = get_user_info(pamh, &username, &service, &rhost, &tty);
    if (retval != PAM_SUCCESS) return retval;

    log_pam_message(LOG_INFO, "Authenticating user: %s via device flow", username);

    /* Phase 1: start the device flow. */
    struct auth_ctx actx = { username, service, rhost, tty, opts.provider };
    if (broker_roundtrip(&opts, AUTH_IO_TIMEOUT, send_auth_cb, &actx, &r) != 0) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* A started device flow is never an authenticated user, but handle an
       "authorized" reply anyway in case a future broker can answer from a
       cached session. */
    if (strcmp(r->status, STATUS_AUTHORIZED) == 0) {
        int ok = authorized_for(r, username);
        /* Same rule as the polling path: store only a session that passed the
           check, and read it out of the reply before it is freed. A cached
           authorization with no session id in it stores nothing, and the account
           stage then answers PAM_IGNORE — correct, since there would be no handle
           to re-check. */
        if (ok) remember_session_id(pamh, r->session_id);
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

    /* Phase 2: show the code and the QR art, then wait.
     *
     * The instructions go out as a prompt rather than PAM_TEXT_INFO because
     * OpenSSH buffers informational messages and may not flush them until
     * pam_sm_authenticate returns — which would show the user the code only
     * after the login had already failed. A prompt forces the text to the
     * screen and gives the user a natural way to say "I have approved".
     */
    char prompt[MAX_PROMPT_SIZE];
    build_device_prompt(prompt, sizeof(prompt), r);
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
       mapper's supplementary groups are advisory — the reply carries them and
       this module never parses them, so no setgroups(2) happens here. The
       container case mapped_groups_not_applied asserts that from the outside.
       Applying them needs a guard against a mapper granting wheel or docker;
       see issue #39. */
    return PAM_SUCCESS;
}

/* pam_sm_acct_mgmt re-asks the broker whether the session this login
   authenticated with is still authorized for this account (issue #75).
 *
 * It used to return PAM_SUCCESS with a comment saying authorization had been
 * decided during authentication. That is true at the instant authentication
 * finishes and stops being true immediately afterwards, which is the entire reason
 * PAM has a separate account stage: between the two, an operator can revoke the
 * enrollment, the provider can revoke the grant, and `oauth2-pam-admin` can delete
 * the session. A module that answers "yes, decided earlier" cannot notice any of
 * it, and an `account required` line naming it is then documentation rather than a
 * control.
 *
 * The cost is one more round trip to a Unix socket on the same host, against a
 * broker that answers check_session out of its own state without leaving the
 * machine — which is why POLL_IO_TIMEOUT and not AUTH_IO_TIMEOUT.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    const char *username = NULL, *service = NULL, *rhost = NULL, *tty = NULL;
    struct module_options opts;
    const void *data = NULL;
    int retval;

    (void)flags;

    parse_arguments(argc, argv, &opts);

    if (validate_socket_path(opts.socket_path) != 0) {
        log_pam_message(LOG_ERR, "Invalid socket path: %s", opts.socket_path);
        return PAM_AUTHINFO_UNAVAIL;
    }

    retval = get_user_info(pamh, &username, &service, &rhost, &tty);
    if (retval != PAM_SUCCESS) return retval;

    /* PAM_NO_MODULE_DATA when the auth stage never stored anything — a login that
       authenticated by some other means, or one where this module was not in the
       auth stack at all. Collapsed into a NULL session id so that account_decision
       is the single place the "not my business" answer is written down. */
    if (pam_get_data(pamh, SESSION_DATA_KEY, &data) != PAM_SUCCESS) {
        data = NULL;
    }

    return account_decision(&opts, username, (const char *)data);
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
