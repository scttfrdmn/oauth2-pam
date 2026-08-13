//go:build linux

package main

// This file is what makes cgo compile cgo_bridge_linux.c into the shared
// object: cgo only builds the C sources of a package that imports "C".
//
// It is Linux-only because the C depends on Linux-PAM (security/pam_ext.h) and
// json-c. The .c file carries a _linux filename suffix rather than a build
// constraint: Go rejects a package that contains C sources but compiles without
// cgo, and that check happens before in-file constraints are read, so on macOS
// the file has to be excluded by name.

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c
#include "cgo_bridge.h"
*/
import "C"
