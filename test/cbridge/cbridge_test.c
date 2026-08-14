/* Unit tests for the C half of the PAM module.
 *
 * The container harness (test/integration/) drives real logins through this code
 * and is the authority on "does a login work". What it cannot reach are the
 * boundaries: a response exactly the size of the buffer, a broker that accepts a
 * connection and then says nothing, a broker that hangs up mid-request. Each of
 * those is a place this module used to hang or fail a working login, and each is
 * cheap to provoke over a socketpair.
 *
 * The implementation is #included rather than linked so that the file-static
 * helpers are testable. There is no separate object file and no header dance:
 * this test *is* a second translation unit of the module.
 *
 * Run it with test/cbridge/run.sh, or `make test-cbridge`.
 */

#include "../../cmd/pam-module/cgo_bridge_linux.c"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...)                                              \
    do {                                                              \
        checks++;                                                     \
        if (!(cond)) {                                                \
            failures++;                                               \
            printf("    FAIL %s:%d: ", __FILE__, __LINE__);           \
            printf(__VA_ARGS__);                                      \
            printf("\n");                                             \
        }                                                             \
    } while (0)

/* ------------------------------------------------------------------ helpers */

/* pair_with_timeout_ms returns a connected socketpair whose first end carries the
   I/O timeout connect_to_broker would have set, in milliseconds — sub-second
   budgets keep the deadline cases quick. Both directions get it, because the
   bridge reads the socket's own timeout back as the budget for a transfer and the
   send path is bounded the same way as the receive path. Tests read from fds[0]
   and play broker on fds[1]. */
static void pair_with_timeout_ms(int fds[2], long timeout_ms) {
    struct timeval tv;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    tv.tv_sec  = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000;
    assert(setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    assert(setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0);
}

static void pair_with_timeout(int fds[2], int timeout_seconds) {
    pair_with_timeout_ms(fds, (long)timeout_seconds * 1000);
}

/* millis_now is the test's own monotonic clock. The deadline cases turn on tenths
   of a second, which monotonic_seconds cannot see. */
static long millis_now(void) {
    struct timespec ts;

    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}

static void write_n(int fd, char byte, size_t n) {
    char *buf = malloc(n);
    assert(buf != NULL);
    memset(buf, byte, n);
    assert(write(fd, buf, n) == (ssize_t)n);
    free(buf);
}

/* ------------------------------------------------- validate_socket_path */

static void test_validate_socket_path(void) {
    printf("  validate_socket_path\n");

    /* Both spellings of the broker's runtime directory. /run is what systemd's
       RuntimeDirectory= creates; accepting only /var/run made a correct
       socket=/run/oauth2-pam/broker.sock fail as "unsafe". */
    CHECK(validate_socket_path("/run/oauth2-pam/broker.sock") == 0,
          "/run path rejected");
    CHECK(validate_socket_path("/var/run/oauth2-pam/broker.sock") == 0,
          "/var/run path rejected");

    /* A sibling directory an unprivileged process could create must not pass
       just because it shares a prefix — this is what the trailing slash in each
       allowed prefix is for. */
    CHECK(validate_socket_path("/run/oauth2-pam-evil/broker.sock") != 0,
          "/run/oauth2-pam-evil accepted");
    CHECK(validate_socket_path("/var/run/oauth2-pam-evil/x.sock") != 0,
          "/var/run/oauth2-pam-evil accepted");

    CHECK(validate_socket_path("/run/oauth2-pam/../../tmp/evil.sock") != 0,
          "traversal accepted");
    CHECK(validate_socket_path("/tmp/broker.sock") != 0, "/tmp accepted");
    CHECK(validate_socket_path("") != 0, "empty path accepted");
    CHECK(validate_socket_path(NULL) != 0, "NULL accepted");

    /* Longer than sun_path can hold. Truncating instead would connect to a
       different socket than the one configured. */
    char too_long[160];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    memcpy(too_long, "/run/oauth2-pam/", strlen("/run/oauth2-pam/"));
    CHECK(validate_socket_path(too_long) != 0, "104+ byte path accepted");
}

/* ------------------------------------------------ receive_auth_response */

static void test_receive_ordinary_response(void) {
    printf("  receive_auth_response: ordinary reply\n");

    int fds[2];
    char buf[RESPONSE_BUF_SIZE];
    const char *body = "{\"status\":\"pending\"}";

    pair_with_timeout(fds, 1);
    assert(write(fds[1], body, strlen(body)) == (ssize_t)strlen(body));
    close(fds[1]);

    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) == 0, "rejected a valid reply");
    CHECK(strcmp(buf, body) == 0, "body mangled: %s", buf);
    close(fds[0]);
}

static void test_receive_response_at_exactly_the_limit(void) {
    printf("  receive_auth_response: exactly MAX_RESPONSE_SIZE bytes\n");

    /* The off-by-one regression. The read loop stops when the buffer is full,
       which used to be indistinguishable from "there is more to come", so a
       complete response of exactly this length was rejected as too large. A
       device-flow reply carries a QR code and is the one reply that can plausibly
       land on the boundary. */
    int fds[2];
    char buf[RESPONSE_BUF_SIZE];

    pair_with_timeout(fds, 1);
    write_n(fds[1], 'x', MAX_RESPONSE_SIZE);
    close(fds[1]);

    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) == 0,
          "rejected a complete %d-byte response", MAX_RESPONSE_SIZE);
    CHECK(strlen(buf) == (size_t)MAX_RESPONSE_SIZE, "stored %zu bytes, want %d",
          strlen(buf), MAX_RESPONSE_SIZE);
    close(fds[0]);
}

static void test_receive_rejects_an_oversized_response(void) {
    printf("  receive_auth_response: one byte over the limit\n");

    int fds[2];
    char buf[RESPONSE_BUF_SIZE];

    pair_with_timeout(fds, 1);
    write_n(fds[1], 'x', MAX_RESPONSE_SIZE + 1);
    close(fds[1]);

    /* Rejected, not truncated: a truncated JSON object is not a parse failure to
       be reported, it is a document that might still parse into something with a
       plausible status field. */
    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) != 0,
          "accepted a response larger than the limit");
    close(fds[0]);
}

static void test_receive_rejects_an_empty_response(void) {
    printf("  receive_auth_response: peer closes with no data\n");

    int fds[2];
    char buf[RESPONSE_BUF_SIZE];

    pair_with_timeout(fds, 1);
    close(fds[1]);

    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) != 0,
          "accepted an empty response");
    close(fds[0]);
}

static void test_receive_times_out_on_a_silent_peer(void) {
    printf("  receive_auth_response: peer accepts then says nothing\n");

    /* The reason connect_to_broker sets SO_RCVTIMEO. A broker that is wedged, or
       stopped between accept() and write(), leaves this call blocked forever;
       the module's own timeout= cannot help, because it is only consulted between
       polls. The login then hangs until sshd's LoginGraceTime kills the session.
       fds[1] is deliberately left open. */
    int fds[2];
    char buf[RESPONSE_BUF_SIZE];
    long start, elapsed;

    pair_with_timeout(fds, 1);
    start = monotonic_seconds();
    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) != 0,
          "a silent peer was treated as a valid reply");
    elapsed = monotonic_seconds() - start;
    CHECK(elapsed < 5, "took %lds; the receive timeout did not apply", elapsed);

    close(fds[0]);
    close(fds[1]);
}

static void test_receive_rejects_a_full_buffer_without_eof(void) {
    printf("  receive_auth_response: buffer full, peer neither closes nor continues\n");

    /* The ambiguous case the boundary probe exists to resolve. We hold exactly
       MAX_RESPONSE_SIZE bytes and cannot know whether that is the whole response,
       so the only safe answer is to refuse it. */
    int fds[2];
    char buf[RESPONSE_BUF_SIZE];

    pair_with_timeout(fds, 1);
    write_n(fds[1], 'x', MAX_RESPONSE_SIZE);

    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) != 0,
          "acted on a possibly-truncated response");

    close(fds[0]);
    close(fds[1]);
}

static void test_receive_bounds_a_drip_feeding_peer(void) {
    printf("  receive_auth_response: peer sends one byte per timeout\n");

    /* The defect a per-syscall timeout cannot catch. SO_RCVTIMEO bounds each
       recv(), so a peer that sends a single byte just inside every timeout extends
       the wait per byte and holds the login open for as long as it likes — a
       16 KB buffer drip-fed at this rate is hours, with an sshd pre-auth child
       held for all of them. "A deadline on every receive" was satisfied and the
       thing it was for was not.

       The child writes a byte every 200ms against a 500ms budget, so the reply
       deadline must end the call after roughly one budget rather than after the
       child stops talking. */
    int fds[2];
    char buf[RESPONSE_BUF_SIZE];
    long start, elapsed;
    pid_t child;

    pair_with_timeout_ms(fds, 500);

    child = fork();
    assert(child != -1);
    if (child == 0) {
        int i;
        close(fds[0]);
        for (i = 0; i < 15; i++) {
            if (write(fds[1], "x", 1) != 1) _exit(0);
            usleep(200000);
        }
        /* Then hold the connection open without closing it, which is what makes
           this a hang rather than a short reply. Bounded so that a module without
           a reply deadline fails this case in a few seconds instead of running
           until the 16 KB buffer fills, which at this rate is nearly an hour. */
        sleep(5);
        _exit(0);
    }
    close(fds[1]);

    start = millis_now();
    CHECK(receive_auth_response(fds[0], buf, sizeof(buf)) != 0,
          "a drip-feeding peer was treated as a valid reply");
    elapsed = millis_now() - start;
    CHECK(elapsed < 1500, "took %ldms against a 500ms budget; the reply deadline did not apply",
          elapsed);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    close(fds[0]);
}

/* ------------------------------------------- transfer deadline helpers */

static void test_transfer_deadline_bounds_a_whole_transfer(void) {
    printf("  transfer_deadline: the budget is the socket's own timeout\n");

    int fds[2];
    struct timespec deadline;
    struct timeval got;
    socklen_t len = sizeof(got);
    long left_ms;

    /* A socket with no timeout has no budget to enforce. Refusing to talk would
       be worse than leaving the caller the per-call bound it already had — and
       connect_to_broker will not hand out such a socket in the first place. */
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    CHECK(transfer_deadline(fds[0], SO_RCVTIMEO, &deadline) == -1,
          "invented a deadline for a socket with no timeout");
    close(fds[0]);
    close(fds[1]);

    /* The send path, which the drip-feed case above cannot reach: making send()
       block needs a peer that stops reading until the socket buffer fills, and the
       module's requests are a few hundred bytes. Exercised through the helper
       instead, on the option the send loop uses. */
    pair_with_timeout_ms(fds, 2000);
    CHECK(transfer_deadline(fds[0], SO_SNDTIMEO, &deadline) == 0,
          "no deadline taken from a 2s SO_SNDTIMEO");

    usleep(300000);
    CHECK(apply_remaining(fds[0], SO_SNDTIMEO, &deadline) == 0,
          "reported the budget spent while 1.7s of it was left");
    assert(getsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &got, &len) == 0);
    left_ms = (long)got.tv_sec * 1000 + got.tv_usec / 1000;
    /* Shrunk, not renewed. A per-call timeout reset to the full budget on every
       iteration is exactly the defect. */
    CHECK(left_ms > 0 && left_ms <= 1700,
          "per-call timeout is %ldms; the remaining budget was not applied", left_ms);

    /* Once the budget is spent the answer is no, rather than one more syscall. */
    assert(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_sec -= 1;
    CHECK(apply_remaining(fds[0], SO_SNDTIMEO, &deadline) == -1,
          "an elapsed deadline was treated as time remaining");

    close(fds[0]);
    close(fds[1]);
}

/* ------------------------------------------------- connect_to_broker */

static int skipped = 0;

static void test_connect_applies_the_io_timeout(void) {
    printf("  connect_to_broker: socket deadlines\n");

    /* Proves the fix is where it has to be. The receive test above sets its own
       timeout on a socketpair, so it only shows that receive_auth_response
       handles EAGAIN; this shows that a socket connect_to_broker hands back
       actually has a deadline on it. Without one, a wedged broker blocks the
       module in recv() until sshd gives up on the whole session.

       It needs the real directory because validate_socket_path — correctly —
       will not accept a path anywhere else, and that means root. */
    const char *dir  = "/run/oauth2-pam";
    const char *path = "/run/oauth2-pam/cbridge-test.sock";
    struct sockaddr_un addr;
    struct timeval got;
    socklen_t len = sizeof(got);
    int listener, sock;

    if (mkdir(dir, 0750) != 0 && errno != EEXIST) {
        printf("    SKIP: cannot create %s (%s); run as root to cover this\n",
               dir, strerror(errno));
        skipped++;
        return;
    }

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listener != -1);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    unlink(path);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("    SKIP: cannot bind %s (%s); run as root to cover this\n",
               path, strerror(errno));
        skipped++;
        close(listener);
        return;
    }
    assert(listen(listener, 1) == 0);

    CHECK(validate_socket_path(path) == 0, "the test's own socket path is rejected");

    sock = connect_to_broker(path, POLL_IO_TIMEOUT);
    CHECK(sock != -1, "failed to connect to a listening socket");
    if (sock != -1) {
        assert(getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &got, &len) == 0);
        CHECK(got.tv_sec == POLL_IO_TIMEOUT, "SO_RCVTIMEO is %lds, want %d",
              (long)got.tv_sec, POLL_IO_TIMEOUT);
        len = sizeof(got);
        assert(getsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &got, &len) == 0);
        CHECK(got.tv_sec == POLL_IO_TIMEOUT, "SO_SNDTIMEO is %lds, want %d",
              (long)got.tv_sec, POLL_IO_TIMEOUT);
        close(sock);
    }

    /* A caller that forgets the deadline must be refused rather than quietly
       given a socket that can block forever. */
    CHECK(connect_to_broker(path, 0) == -1, "connected with no I/O timeout");

    close(listener);
    unlink(path);
}

/* ----------------------------------------------------------- send_json */

static void test_send_json_survives_a_closed_peer(void) {
    printf("  send_json: peer has hung up\n");

    /* If this test crashes rather than fails, that *is* the bug: without
       MSG_NOSIGNAL, send() to a closed peer raises SIGPIPE, whose default
       disposition terminates the process. In production that process is sshd's
       pre-auth child, so a broker restart mid-login would drop the connection
       instead of failing the module. A PAM module cannot install a handler to
       avoid this — the disposition belongs to the host application. */
    int fds[2];
    json_object *req = json_object_new_object();
    json_object_object_add(req, "type", json_object_new_string("check_session"));

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    close(fds[1]);

    CHECK(send_json(fds[0], req) != 0, "reported success writing to a closed peer");

    json_object_put(req);
    close(fds[0]);
}

/* ------------------------------------------------- send_auth_request */

/* read_sent_request runs send_auth_request over a socketpair and returns the
   parsed JSON it put on the wire. Caller frees with json_object_put. */
static json_object *read_sent_request(const char *username, const char *service,
                                      const char *rhost, const char *tty,
                                      const char *provider) {
    int fds[2];
    char buf[4096];
    ssize_t n;
    json_object *sent;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    assert(send_auth_request(fds[0], username, service, rhost, tty, provider) == 0);
    close(fds[0]);

    n = recv(fds[1], buf, sizeof(buf) - 1, 0);
    assert(n > 0);
    buf[n] = '\0';
    close(fds[1]);

    sent = json_tokener_parse(buf);
    assert(sent != NULL);
    return sent;
}

static const char *field(json_object *obj, const char *key) {
    json_object *v = NULL;
    if (!json_object_object_get_ex(obj, key, &v)) return NULL;
    return json_object_get_string(v);
}

static void test_send_auth_request_fields(void) {
    printf("  send_auth_request: which field carries what\n");

    /* The regression this pins down: the module used to send PAM_RHOST as
       target_host and never send source_ip at all, so every audit record named
       the client as the host being logged into and left the origin blank. Both
       fields were populated, and both were wrong. copy_source_ip and
       copy_target_host being right does not prove they are wired up — only
       inspecting the bytes on the wire does. */
    char expected_host[MAX_HOSTNAME_LEN];
    assert(gethostname(expected_host, sizeof(expected_host)) == 0);
    expected_host[sizeof(expected_host) - 1] = '\0';

    json_object *req = read_sent_request("alice", "sshd", "192.0.2.10", "ssh", NULL);
    const char *v;

    CHECK((v = field(req, "type")) && strcmp(v, "authenticate") == 0, "type wrong");
    CHECK((v = field(req, "user_id")) && strcmp(v, "alice") == 0, "user_id wrong");
    CHECK((v = field(req, "login_type")) && strcmp(v, "ssh") == 0, "login_type wrong");
    CHECK((v = field(req, "source_ip")) && strcmp(v, "192.0.2.10") == 0,
          "source_ip = %s, want the client address", v ? v : "(absent)");
    CHECK((v = field(req, "target_host")) && strcmp(v, expected_host) == 0,
          "target_host = %s, want this host (%s)", v ? v : "(absent)", expected_host);

    json_object *meta = NULL;
    CHECK(json_object_object_get_ex(req, "metadata", &meta), "metadata absent");
    if (meta != NULL) {
        CHECK((v = field(meta, "rhost")) && strcmp(v, "192.0.2.10") == 0,
              "metadata.rhost = %s", v ? v : "(absent)");
        CHECK((v = field(meta, "service")) && strcmp(v, "sshd") == 0, "metadata.service wrong");
    }

    /* Omitted, not sent empty, so the request is byte-identical to what a module
       without a provider= argument used to send. */
    CHECK(field(req, "provider") == NULL, "provider sent when none was configured");
    json_object_put(req);

    req = read_sent_request("alice", "sshd", "192.0.2.10", "ssh", "github");
    CHECK((v = field(req, "provider")) && strcmp(v, "github") == 0, "provider= not forwarded");
    json_object_put(req);

    /* A resolved name is not an address: it goes in metadata, and source_ip stays
       empty rather than risking the broker's 45-byte cap on the whole request. */
    req = read_sent_request("alice", "sshd", "client.example.com", "ssh", NULL);
    CHECK((v = field(req, "source_ip")) && v[0] == '\0',
          "source_ip = %s, want empty for a hostname", v ? v : "(absent)");
    CHECK(json_object_object_get_ex(req, "metadata", &meta) &&
              (v = field(meta, "rhost")) && strcmp(v, "client.example.com") == 0,
          "the resolved name was lost");
    json_object_put(req);

    /* A console login has no remote host at all. */
    req = read_sent_request("alice", "login", "", "tty1", NULL);
    CHECK((v = field(req, "login_type")) && strcmp(v, "console") == 0,
          "login_type = %s for a tty", v ? v : "(absent)");
    CHECK((v = field(req, "source_ip")) && v[0] == '\0', "source_ip invented for a console login");
    json_object_put(req);
}

/* ------------------------------------------------- source_ip / target_host */

static void test_source_ip_takes_only_addresses(void) {
    printf("  copy_source_ip\n");

    char ip[MAX_SOURCE_IP_LEN];

    copy_source_ip("192.0.2.10", ip, sizeof(ip));
    CHECK(strcmp(ip, "192.0.2.10") == 0, "IPv4 dropped: got %s", ip);

    copy_source_ip("2001:db8::1", ip, sizeof(ip));
    CHECK(strcmp(ip, "2001:db8::1") == 0, "IPv6 dropped: got %s", ip);

    /* With `UseDNS yes` PAM_RHOST is a name, and a fully qualified one can exceed
       the 45 bytes the broker allows for source_ip — which would make it reject
       the whole request and fail the login. A name belongs in metadata.rhost, not
       here. */
    copy_source_ip("client.example.com", ip, sizeof(ip));
    CHECK(ip[0] == '\0', "hostname accepted as an address: %s", ip);

    /* get_user_info leaves rhost empty for a console login rather than claiming
       "localhost", so this is the ordinary local case, not an error. */
    copy_source_ip("", ip, sizeof(ip));
    CHECK(ip[0] == '\0', "empty rhost produced %s", ip);
    copy_source_ip(NULL, ip, sizeof(ip));
    CHECK(ip[0] == '\0', "NULL rhost produced %s", ip);

    copy_source_ip("not an address at all", ip, sizeof(ip));
    CHECK(ip[0] == '\0', "garbage accepted as an address: %s", ip);
}

static void test_target_host_is_this_host(void) {
    printf("  copy_target_host\n");

    /* target_host means the host being logged into. The module used to send
       PAM_RHOST here, so every audit record named the client as the target and
       left source_ip empty: both fields populated, both wrong. */
    char host[MAX_HOSTNAME_LEN];
    char expected[MAX_HOSTNAME_LEN];

    assert(gethostname(expected, sizeof(expected)) == 0);
    expected[sizeof(expected) - 1] = '\0';

    copy_target_host(host, sizeof(host));
    CHECK(strcmp(host, expected) == 0, "got %s, want %s", host, expected);
}

/* --------------------------------------------- parse_broker_response */

static void test_parse_reads_the_error_code(void) {
    printf("  parse_broker_response: error_code\n");

    struct broker_response *r = NULL;

    /* RATE_LIMITED arrives as status "error", indistinguishable from a real
       failure unless the code is read. Treating it as terminal failed logins
       that were only being asked to slow down. */
    CHECK(parse_broker_response(
              "{\"status\":\"error\",\"error_code\":\"RATE_LIMITED\","
              "\"error_message\":\"Too many requests\"}", &r) == 0,
          "failed to parse a rate-limit reply");
    if (r != NULL) {
        CHECK(strcmp(r->error_code, "RATE_LIMITED") == 0, "error_code = %s", r->error_code);
        CHECK(is_rate_limited(r) == 1, "rate-limit reply not recognized");
        free(r);
        r = NULL;
    }

    CHECK(parse_broker_response(
              "{\"status\":\"error\",\"error_code\":\"DEVICE_FLOW_FAILED\"}", &r) == 0,
          "failed to parse an error reply");
    if (r != NULL) {
        CHECK(is_rate_limited(r) == 0, "an ordinary error was treated as throttling");
        free(r);
        r = NULL;
    }

    /* An older broker sends no error_code at all. */
    CHECK(parse_broker_response("{\"status\":\"pending\",\"session_id\":\"abc\"}", &r) == 0,
          "failed to parse a reply without error_code");
    if (r != NULL) {
        CHECK(r->error_code[0] == '\0', "absent error_code became %s", r->error_code);
        CHECK(is_rate_limited(r) == 0, "absent error_code read as throttling");
        free(r);
        r = NULL;
    }

    CHECK(parse_broker_response("not json", &r) != 0, "accepted non-JSON");
    CHECK(parse_broker_response("[1,2,3]", &r) != 0, "accepted a JSON array");
}

static void test_parse_reads_success_strictly(void) {
    printf("  parse_broker_response: success is a boolean or nothing\n");

    struct broker_response *r = NULL;

    CHECK(parse_broker_response(
              "{\"success\":true,\"status\":\"authorized\",\"user_id\":\"alice\"}", &r) == 0,
          "failed to parse success=true");
    if (r != NULL) {
        CHECK(r->success == 1, "success=true read as %d", r->success);
        free(r);
        r = NULL;
    }

    CHECK(parse_broker_response("{\"success\":false,\"status\":\"denied\"}", &r) == 0,
          "failed to parse success=false");
    if (r != NULL) {
        CHECK(r->success == 0, "success=false read as %d", r->success);
        free(r);
        r = NULL;
    }

    /* json_object_get_boolean coerces, so reading this field without checking its
       type made "false" — a non-empty string — read as true, and the module would
       grant a login off a reply that said the opposite. The wrong type here is a
       malformed reply, refused outright, which the caller turns into
       PAM_AUTHINFO_UNAVAIL. */
    CHECK(parse_broker_response(
              "{\"success\":\"false\",\"status\":\"authorized\",\"user_id\":\"alice\"}", &r) != 0,
          "a string success was accepted; \"false\" would read as true");
    CHECK(parse_broker_response(
              "{\"success\":1,\"status\":\"authorized\",\"user_id\":\"alice\"}", &r) != 0,
          "an integer success was accepted");
    CHECK(parse_broker_response(
              "{\"success\":null,\"status\":\"authorized\",\"user_id\":\"alice\"}", &r) != 0,
          "a null success was accepted");
    CHECK(parse_broker_response(
              "{\"success\":{},\"status\":\"authorized\",\"user_id\":\"alice\"}", &r) != 0,
          "an object success was accepted");

    /* Absent is not malformed — nothing on the wire requires the field — but it
       is not true either: authorized_for refuses a reply that never said it
       succeeded. */
    CHECK(parse_broker_response("{\"status\":\"pending\",\"session_id\":\"abc\"}", &r) == 0,
          "a reply without success was rejected");
    if (r != NULL) {
        CHECK(r->success == 0, "absent success read as %d", r->success);
        free(r);
        r = NULL;
    }
}

/* --------------------------------------------------- protocol versioning */

static void test_protocol_version(void) {
    printf("  protocol_version: read, and refused when unknown\n");

    struct broker_response *r = NULL;

    /* The version this module speaks. Accepted, obviously — but assert it, so
       that bumping PROTOCOL_VERSION without teaching the module the new contract
       fails here rather than in production. */
    char reply[128];
    snprintf(reply, sizeof(reply),
             "{\"protocol_version\":%d,\"status\":\"pending\",\"session_id\":\"abc\"}",
             PROTOCOL_VERSION);
    CHECK(parse_broker_response(reply, &r) == 0, "failed to parse a same-version reply");
    if (r != NULL) {
        CHECK(r->protocol_version == PROTOCOL_VERSION,
              "protocol_version = %d, want %d", r->protocol_version, PROTOCOL_VERSION);
        CHECK(protocol_version_supported(r) == 1, "own version refused");
        free(r);
        r = NULL;
    }

    /* A v0.2.x broker sends no protocol_version. It must still be accepted:
       version 1 is what it speaks, and refusing it would break a host where the
       broker has not been restarted yet. */
    CHECK(parse_broker_response("{\"status\":\"authorized\",\"user_id\":\"alice\"}", &r) == 0,
          "failed to parse a reply without protocol_version");
    if (r != NULL) {
        CHECK(r->protocol_version == 0, "absent protocol_version became %d", r->protocol_version);
        CHECK(protocol_version_supported(r) == 1,
              "a broker predating the field was refused; that breaks an in-place upgrade");
        free(r);
        r = NULL;
    }

    /* A future contract. The reply parses and says "authorized" for a real user,
       which is exactly why it has to be refused: this module cannot know what
       that word means in a contract it does not implement. */
    CHECK(parse_broker_response(
              "{\"protocol_version\":2,\"success\":true,\"status\":\"authorized\","
              "\"user_id\":\"alice\"}", &r) == 0,
          "failed to parse a version-2 reply");
    if (r != NULL) {
        CHECK(r->protocol_version == 2, "protocol_version = %d, want 2", r->protocol_version);
        CHECK(protocol_version_supported(r) == 0,
              "a version-2 reply was accepted; \"authorized\" was read under the wrong contract");
        free(r);
        r = NULL;
    }

    /* Junk in the field is not version 1 by default. A string, a float or a
       negative number all leave it at 0, which reads as "the field is absent" —
       that is the deliberate choice, because the alternative is inventing a
       version number for a broker that sent nonsense. What must not happen is a
       nonsense value being treated as a *known* version other than 1. */
    CHECK(parse_broker_response(
              "{\"protocol_version\":\"two\",\"status\":\"pending\"}", &r) == 0,
          "failed to parse a reply with a non-integer protocol_version");
    if (r != NULL) {
        CHECK(r->protocol_version == 0, "a string protocol_version became %d", r->protocol_version);
        free(r);
        r = NULL;
    }

    CHECK(parse_broker_response("{\"protocol_version\":-1,\"status\":\"pending\"}", &r) == 0,
          "failed to parse a reply with a negative protocol_version");
    if (r != NULL) {
        CHECK(protocol_version_supported(r) == 0, "a negative protocol_version was accepted");
        free(r);
        r = NULL;
    }

    CHECK(protocol_version_supported(NULL) == 0, "a NULL response was called supported");

    /* Both request types must declare the version, or a broker that starts
       enforcing it refuses every login this module attempts. */
    json_object *req = read_sent_request("alice", "sshd", "192.0.2.10", "ssh", NULL);
    json_object *pv = NULL;
    CHECK(json_object_object_get_ex(req, "protocol_version", &pv) &&
              json_object_get_int(pv) == PROTOCOL_VERSION,
          "authenticate did not declare protocol_version %d", PROTOCOL_VERSION);
    json_object_put(req);
}

/* ------------------------------------------------------- the grant decision */

/* parsed returns the broker_response for one JSON reply, or NULL if it did not
   parse. Caller frees. Going through parse_broker_response rather than filling
   the struct by hand keeps these tests honest about the path a real reply
   takes: the fields the decision reads are the fields the parser wrote. */
static struct broker_response *parsed(const char *json_text) {
    struct broker_response *r = NULL;

    if (parse_broker_response(json_text, &r) != 0) return NULL;
    return r;
}

static void test_authorized_for(void) {
    printf("  authorized_for: the client half of the grant decision\n");

    /* This is the whole client half of the contract docs/wire-protocol.md
       describes as "two independent checks, because one of them is in a
       different process and might be an older version of itself". The broker
       enforces the same rule before it activates a session; this is the second,
       independent check on the value the module is about to act on.

       Until this test existed, nothing in the repository called it — neither the
       unit suite nor any mutation nor the container harness, which drives an
       honest broker and so can never answer "authorized" for the wrong user. So
       `authorized_for() { return 1; }` was green in every suite here, which is
       the exact shape of an authorization bypass that ships. */
    struct broker_response *r;

    r = parsed("{\"success\":true,\"status\":\"authorized\",\"user_id\":\"alice\"}");
    CHECK(r != NULL, "a well-formed authorized reply did not parse");
    if (r != NULL) {
        CHECK(authorized_for(r, "alice") == 1, "refused an authorized reply for the right user");

        /* The bypass. A reply that says "authorized" for a different account
           must never open a shell as the one the login asked for. */
        CHECK(authorized_for(r, "bob") == 0, "a reply authorizing alice opened a login for bob");

        /* Not a prefix comparison: alic and alicia are different accounts, and a
           strncmp with the wrong length is how this quietly stops being a
           comparison at all. */
        CHECK(authorized_for(r, "alic") == 0, "a prefix of the authorized user was accepted");
        CHECK(authorized_for(r, "alicia") == 0, "an extension of the authorized user was accepted");
        /* Unix accounts are case-sensitive, so Alice is not alice. */
        CHECK(authorized_for(r, "Alice") == 0, "the comparison was case-insensitive");
        CHECK(authorized_for(r, "") == 0, "an empty login name matched a named user");
        free(r);
    }

    /* status and success are two statements about the same outcome, and a reply
       where they disagree is not a reply this module can act on: whichever one is
       wrong, it does not know which. Failing closed is the only answer. */
    r = parsed("{\"success\":false,\"status\":\"authorized\",\"user_id\":\"alice\"}");
    CHECK(r != NULL, "an authorized/success=false reply did not parse");
    if (r != NULL) {
        CHECK(authorized_for(r, "alice") == 0, "status=authorized with success=false granted a login");
        free(r);
    }

    /* A reply that never says it succeeded has not. */
    r = parsed("{\"status\":\"authorized\",\"user_id\":\"alice\"}");
    CHECK(r != NULL, "a reply without success did not parse");
    if (r != NULL) {
        CHECK(authorized_for(r, "alice") == 0, "an absent success was read as true");
        free(r);
    }

    /* An empty user_id is not "no opinion", it is a reply that authorized nobody
       — and it would compare equal to an empty PAM username. Refused before the
       comparison, so that neither side of it can be empty. */
    r = parsed("{\"success\":true,\"status\":\"authorized\",\"user_id\":\"\"}");
    CHECK(r != NULL, "a reply with an empty user_id did not parse");
    if (r != NULL) {
        CHECK(authorized_for(r, "") == 0, "an empty user_id authorized an empty username");
        CHECK(authorized_for(r, "alice") == 0, "an empty user_id authorized alice");
        free(r);
    }
}

static void test_terminal_status_to_pam(void) {
    printf("  terminal_status_to_pam: a terminal status is never a login\n");

    /* The other half of the decision, and equally uncovered until now: deleting
       this mapping was green in every suite here too.

       Two things are asserted of every case. First that it is not PAM_SUCCESS —
       no terminal status is a login. Second *which* failure it is, because the
       two are not interchangeable in a stack: a decision about the user is
       PAM_AUTH_ERR, while an operational failure is PAM_AUTHINFO_UNAVAIL, which
       invites the rest of the stack to answer instead. Reporting a denial as
       "ask someone else" is how a provider's "no" becomes somebody else's yes. */
    struct broker_response *r;
    int rc;

    r = parsed("{\"status\":\"denied\",\"error_message\":\"not a member of the team\"}");
    CHECK(r != NULL, "a denied reply did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTH_ERR, "denied mapped to %d, want PAM_AUTH_ERR (%d)", rc, PAM_AUTH_ERR);
        free(r);
    }

    r = parsed("{\"status\":\"expired\",\"error_message\":\"the code expired\"}");
    CHECK(r != NULL, "an expired reply did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTH_ERR, "expired mapped to %d, want PAM_AUTH_ERR (%d)", rc, PAM_AUTH_ERR);
        free(r);
    }

    /* Capacity conditions are not decisions about the user: the host is busy,
       not the account unwelcome. PAM_AUTHINFO_UNAVAIL — "ask someone else, or
       try again" — is the honest answer. */
    r = parsed("{\"status\":\"error\",\"error_code\":\"RATE_LIMITED\"}");
    CHECK(r != NULL, "a rate-limited reply did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTHINFO_UNAVAIL, "RATE_LIMITED mapped to %d, want PAM_AUTHINFO_UNAVAIL (%d)",
              rc, PAM_AUTHINFO_UNAVAIL);
        free(r);
    }

    r = parsed("{\"status\":\"error\",\"error_code\":\"AUTH_LIMIT_REACHED\"}");
    CHECK(r != NULL, "an at-capacity reply did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTHINFO_UNAVAIL,
              "AUTH_LIMIT_REACHED mapped to %d, want PAM_AUTHINFO_UNAVAIL (%d)",
              rc, PAM_AUTHINFO_UNAVAIL);
        free(r);
    }

    r = parsed("{\"status\":\"error\",\"error_code\":\"DEVICE_FLOW_FAILED\","
               "\"error_message\":\"provider unreachable\"}");
    CHECK(r != NULL, "an error reply did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTHINFO_UNAVAIL, "an operational error mapped to %d, want %d",
              rc, PAM_AUTHINFO_UNAVAIL);
        free(r);
    }

    /* A status this module does not know must fail closed. It is the branch a
       future broker reaches first, and the one place where "unrecognized" could
       most easily be read as "nothing wrong". */
    r = parsed("{\"status\":\"granted\",\"user_id\":\"alice\",\"success\":true}");
    CHECK(r != NULL, "a reply with an unknown status did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTH_ERR, "an unknown status mapped to %d, want PAM_AUTH_ERR (%d)",
              rc, PAM_AUTH_ERR);
        free(r);
    }

    /* An absent status parses to the empty string, which is no status at all. */
    r = parsed("{\"success\":true,\"user_id\":\"alice\"}");
    CHECK(r != NULL, "a reply with no status did not parse");
    if (r != NULL) {
        rc = terminal_status_to_pam(r, "alice");
        CHECK(rc == PAM_AUTH_ERR, "a missing status mapped to %d, want PAM_AUTH_ERR (%d)",
              rc, PAM_AUTH_ERR);
        free(r);
    }
}

/* ------------------------------------------------------ parse_arguments */

static void test_parse_arguments(void) {
    printf("  parse_arguments\n");

    struct module_options opts;

    const char *none[] = { NULL };
    parse_arguments(0, none, &opts);
    CHECK(strcmp(opts.socket_path, DEFAULT_SOCKET_PATH) == 0, "default socket wrong");
    CHECK(opts.provider == NULL, "default provider is not NULL");
    CHECK(opts.poll_interval == DEFAULT_POLL_INTERVAL, "default poll_interval wrong");
    CHECK(opts.auth_timeout == DEFAULT_AUTH_TIMEOUT, "default timeout wrong");
    CHECK(opts.debug == 0, "debug on by default");

    const char *all[] = {
        "socket=/run/oauth2-pam/broker.sock", "provider=github",
        "poll_interval=3", "timeout=60", "debug",
    };
    parse_arguments(5, all, &opts);
    CHECK(strcmp(opts.socket_path, "/run/oauth2-pam/broker.sock") == 0, "socket= ignored");
    CHECK(opts.provider != NULL && strcmp(opts.provider, "github") == 0, "provider= ignored");
    CHECK(opts.poll_interval == 3, "poll_interval= ignored");
    CHECK(opts.auth_timeout == 60, "timeout= ignored");
    CHECK(opts.debug == 1, "debug ignored");

    /* Out-of-range values fall back to the default rather than being clamped or
       taken literally: timeout=0 would make every login fail instantly, and
       poll_interval=0 would spin. */
    const char *bad[] = { "poll_interval=0", "timeout=0" };
    parse_arguments(2, bad, &opts);
    CHECK(opts.poll_interval == DEFAULT_POLL_INTERVAL, "poll_interval=0 accepted");
    CHECK(opts.auth_timeout == DEFAULT_AUTH_TIMEOUT, "timeout=0 accepted");

    const char *huge[] = { "poll_interval=99999", "timeout=99999" };
    parse_arguments(2, huge, &opts);
    CHECK(opts.poll_interval == DEFAULT_POLL_INTERVAL, "absurd poll_interval accepted");
    CHECK(opts.auth_timeout == DEFAULT_AUTH_TIMEOUT, "absurd timeout accepted");

    /* The default must stay under sshd's LoginGraceTime (120s), or the module's
       deadline is unreachable and the user sees an abrupt disconnect instead of a
       timeout message. */
    CHECK(DEFAULT_AUTH_TIMEOUT < 120, "DEFAULT_AUTH_TIMEOUT is not under LoginGraceTime");

    /* The authenticate round trip must outlast the broker's own provider HTTP
       timeout (30s in pkg/provider/github), or a slow-but-working device flow
       start is aborted by the client. */
    CHECK(AUTH_IO_TIMEOUT > 30, "AUTH_IO_TIMEOUT does not cover the provider timeout");
    CHECK(AUTH_IO_TIMEOUT < DEFAULT_AUTH_TIMEOUT, "AUTH_IO_TIMEOUT exceeds the login deadline");
    CHECK(POLL_IO_TIMEOUT < AUTH_IO_TIMEOUT, "POLL_IO_TIMEOUT is not tighter than AUTH_IO_TIMEOUT");

    debug_enabled = 0;
}

/* ---------------------------------------------------------------- main */

int main(void) {
    printf("cbridge tests\n");

    /* Pin SIGPIPE to its default disposition, because a signal disposition is
       inherited across exec() and this suite's protection against a missing
       MSG_NOSIGNAL depends entirely on it.

       With SIGPIPE ignored, send() to a closed peer returns EPIPE instead of
       killing the process, so send_json reports the failure either way and
       test_send_json_survives_a_closed_peer passes with or without
       MSG_NOSIGNAL. That is not a hypothetical: the mutation check ran green on
       macOS under Docker (default disposition) and simultaneously MISSED the
       mutation on the GitHub Linux runner, whose process tree ignores SIGPIPE.
       For a while the suite reported that it was pinning this defect down while
       pinning nothing.

       Resetting it here is also the faithful thing to do rather than merely the
       convenient one: in production this code runs inside sshd's pre-auth child,
       a process whose SIGPIPE disposition the module does not choose and cannot
       rely on. Testing under the disposition that kills is testing the case that
       matters. */
    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
        printf("FATAL: could not reset SIGPIPE to SIG_DFL: %s\n", strerror(errno));
        return 1;
    }
    /* And confirm it took, so this cannot quietly stop working. */
    {
        struct sigaction sa;
        CHECK(sigaction(SIGPIPE, NULL, &sa) == 0, "could not read back SIGPIPE disposition");
        CHECK(sa.sa_handler == SIG_DFL,
              "SIGPIPE is not SIG_DFL; a missing MSG_NOSIGNAL would go undetected");
    }

    test_validate_socket_path();
    test_receive_ordinary_response();
    test_receive_response_at_exactly_the_limit();
    test_receive_rejects_an_oversized_response();
    test_receive_rejects_an_empty_response();
    test_receive_times_out_on_a_silent_peer();
    test_receive_rejects_a_full_buffer_without_eof();
    test_receive_bounds_a_drip_feeding_peer();
    test_transfer_deadline_bounds_a_whole_transfer();
    test_connect_applies_the_io_timeout();
    test_send_json_survives_a_closed_peer();
    test_send_auth_request_fields();
    test_source_ip_takes_only_addresses();
    test_target_host_is_this_host();
    test_parse_reads_the_error_code();
    test_parse_reads_success_strictly();
    test_protocol_version();
    test_authorized_for();
    test_terminal_status_to_pam();
    test_parse_arguments();

    printf("\n%d checks, %d failures", checks, failures);
    if (skipped > 0) printf(", %d test(s) skipped", skipped);
    printf("\n");

    /* A skip is a failure by default. Some of these tests need root — the module
       runs as root in production, so that is not an unreasonable thing to ask —
       and a suite that reports success while quietly omitting them stops
       protecting anything it was written to protect. Set CBRIDGE_ALLOW_SKIP=1 to
       run the rest anyway. */
    if (skipped > 0 && getenv("CBRIDGE_ALLOW_SKIP") == NULL) {
        printf("skipped tests count as failures; re-run as root, "
               "or set CBRIDGE_ALLOW_SKIP=1 to accept the gap\n");
        return 1;
    }
    return failures == 0 ? 0 : 1;
}
