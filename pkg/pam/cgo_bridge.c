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

    if (pam_get_item(pamh, PAM_SERVICE, (const void**)service) != PAM_SUCCESS)
        *service = "unknown";
    if (pam_get_item(pamh, PAM_RHOST,   (const void**)rhost)   != PAM_SUCCESS)
        *rhost = "localhost";
    if (pam_get_item(pamh, PAM_TTY,     (const void**)tty)     != PAM_SUCCESS)
        *tty = "unknown";

    log_pam_message(LOG_DEBUG, "user=%s service=%s rhost=%s tty=%s",
                    *username, *service, *rhost, *tty);
    return PAM_SUCCESS;
}

int send_auth_request(int sock, const char *username, const char *service,
                      const char *rhost, const char *tty) {
    json_object *req      = json_object_new_object();
    json_object *metadata = json_object_new_object();
    const char *login_type = "unknown";

    if (strcmp(service, "sshd") == 0)
        login_type = "ssh";
    else if (strstr(tty, "tty") != NULL)
        login_type = "console";
    else if (strstr(service, "gdm") != NULL || strstr(service, "lightdm") != NULL)
        login_type = "gui";

    json_object_object_add(metadata, "service", json_object_new_string(service));
    json_object_object_add(metadata, "tty",     json_object_new_string(tty));
    json_object_object_add(metadata, "pid",     json_object_new_int(getpid()));

    json_object_object_add(req, "type",        json_object_new_string("authenticate"));
    json_object_object_add(req, "user_id",     json_object_new_string(username));
    json_object_object_add(req, "login_type",  json_object_new_string(login_type));
    json_object_object_add(req, "target_host", json_object_new_string(rhost));
    json_object_object_add(req, "metadata",    metadata);

    const char *req_str = json_object_to_json_string(req);
    size_t req_len = strlen(req_str);

    log_pam_message(LOG_DEBUG, "Sending auth request: %s", req_str);

    ssize_t sent = send(sock, req_str, req_len, 0);
    json_object_put(req);

    if (sent == -1 || (size_t)sent != req_len) {
        log_pam_message(LOG_ERR, "Failed to send request: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int receive_auth_response(int sock, char *response, size_t response_size) {
    ssize_t received = recv(sock, response, response_size - 1, 0);
    if (received <= 0) {
        log_pam_message(LOG_ERR, "Failed to receive response: %s",
                        received == 0 ? "connection closed" : strerror(errno));
        return -1;
    }
    response[received] = '\0';
    log_pam_message(LOG_DEBUG, "Received response: %s", response);
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

    msg.msg_style = PAM_TEXT_INFO;
    msg.msg = message;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (resp) {
        if (resp->resp) free(resp->resp);
        free(resp);
    }
    return retval;
}

int prompt_user(pam_handle_t *pamh, const char *prompt, char *response, size_t response_size) {
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;
    int retval;

    retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (retval != PAM_SUCCESS) return retval;

    msg.msg_style = PAM_PROMPT_ECHO_ON;
    msg.msg = prompt;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval == PAM_SUCCESS && resp && resp->resp) {
        strncpy(response, resp->resp, response_size - 1);
        response[response_size - 1] = '\0';
        free(resp->resp);
        free(resp);
    } else {
        response[0] = '\0';
    }
    return retval;
}

static void parse_arguments(int argc, const char **argv) {
    int i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            debug_enabled = 1;
        }
    }
}

/* Helper: read socket path from PAM args (socket=/path) or use default */
static const char *get_socket_path(int argc, const char **argv) {
    int i;
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "socket=", 7) == 0) {
            return argv[i] + 7;
        }
    }
    return DEFAULT_SOCKET_PATH;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *username, *service, *rhost, *tty, *socket_path;
    char response[MAX_BUFFER_SIZE];
    int sock, retval;

    parse_arguments(argc, argv);
    socket_path = get_socket_path(argc, argv);

    log_pam_message(LOG_INFO, "%s v%s authentication started", PAM_MODULE_NAME, PAM_MODULE_VERSION);

    retval = get_user_info(pamh, &username, &service, &rhost, &tty);
    if (retval != PAM_SUCCESS) return retval;

    log_pam_message(LOG_INFO, "Authenticating user: %s via GitHub", username);

    sock = connect_to_broker(socket_path);
    if (sock == -1) return PAM_AUTHINFO_UNAVAIL;

    if (send_auth_request(sock, username, service, rhost, tty) != 0) {
        close(sock);
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (receive_auth_response(sock, response, sizeof(response)) != 0) {
        close(sock);
        return PAM_AUTHINFO_UNAVAIL;
    }
    close(sock);

    json_object *resp_obj = json_tokener_parse(response);
    if (!resp_obj) {
        log_pam_message(LOG_ERR, "Failed to parse broker response");
        return PAM_AUTHINFO_UNAVAIL;
    }

    json_object *success_obj = NULL;
    if (!json_object_object_get_ex(resp_obj, "success", &success_obj)) {
        json_object_put(resp_obj);
        return PAM_AUTHINFO_UNAVAIL;
    }

    int success = json_object_get_boolean(success_obj);

    if (success) {
        log_pam_message(LOG_INFO, "Authentication successful for user: %s", username);
        json_object_put(resp_obj);
        return PAM_SUCCESS;
    }

    /* Check whether device flow instructions need to be shown */
    json_object *req_dev_obj = NULL;
    if (json_object_object_get_ex(resp_obj, "requires_device", &req_dev_obj) &&
        json_object_get_boolean(req_dev_obj)) {
        json_object *instr_obj = NULL;
        if (json_object_object_get_ex(resp_obj, "instructions", &instr_obj)) {
            display_message(pamh, json_object_get_string(instr_obj));
        }
        log_pam_message(LOG_INFO, "Device authorization required for user: %s", username);
        json_object_put(resp_obj);
        /* Return AUTHINFO_UNAVAIL so the user retries; the broker polls in the
           background and will return success on the next authenticate call once
           the device flow is approved. */
        return PAM_AUTHINFO_UNAVAIL;
    }

    json_object *errmsg_obj = NULL;
    if (json_object_object_get_ex(resp_obj, "error_message", &errmsg_obj)) {
        log_pam_message(LOG_ERR, "Authentication failed: %s",
                        json_object_get_string(errmsg_obj));
    }

    json_object_put(resp_obj);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    parse_arguments(argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    parse_arguments(argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    parse_arguments(argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    parse_arguments(argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    parse_arguments(argc, argv);
    /* Password changes are handled by the identity provider (GitHub), not PAM */
    return PAM_AUTHTOK_ERR;
}
