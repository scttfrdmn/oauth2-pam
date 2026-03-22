package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../pkg/pam -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c
#include "cgo_bridge.h"
*/
import "C"

// This package produces the PAM shared library (pam_oauth2.so).
// The PAM entry points (pam_sm_authenticate, pam_sm_acct_mgmt, etc.) are
// implemented in C (cgo_bridge.h / cgo_bridge.c) and call back into the
// broker via the Unix socket. This Go main() is never called at runtime.

func main() {}
