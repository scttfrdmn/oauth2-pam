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

// The compile line below is the only place the artifact that goes into sshd —
// as root, in a process that also holds the pre-auth network connection — gets
// any hardening at all. It used to be two -I flags: no stack protector, no
// fortified libc calls, no read-only relocations, and none of the warnings
// test/cbridge/ has always compiled the same C with. The code is warning-clean
// under -Wall -Wextra -Wconversion, which is exactly why turning them on here
// costs nothing today and is worth doing before it does.
//
// Notes on the choices, because each one is a trade rather than a default:
//
//   -Werror, on a *release* artifact, is a deliberate risk: a future compiler
//   that warns about untouched code turns a build into a failure. It is taken
//   because the alternative is a warning nobody reads in a module that runs as
//   root, and because CI builds this on a pinned image.
//
//   -D_FORTIFY_SOURCE=2, not 3. Level 3 needs gcc 12 and glibc 2.35; on an older
//   toolchain glibc's features.h answers with a #warning, which -Werror above
//   would turn into a build failure on exactly the enterprise distributions this
//   module is meant to install on. -U first because Debian's and Ubuntu's gcc
//   already define it, and a redefinition is itself a warning.
//
//   -fstack-clash-protection is x86-64 and aarch64 only; both are the release
//   targets. -fcf-protection is deliberately absent: it is x86-only and would
//   break the aarch64 build outright rather than warn.
//
//   No -fPIE/-pie: -buildmode=c-shared produces a shared object, which is
//   already position-independent, and -pie on a .so is a link error. Should #65
//   land and this become a plain `cc -shared` module, the flags move with it.
//
// Verify the mitigations actually took on the built .so rather than trusting
// this comment:
//
//	readelf -lWd bin/oauth2_pam.so | grep -E 'GNU_RELRO|BIND_NOW|FLAGS'
//	nm -D --undefined-only bin/oauth2_pam.so | grep __stack_chk_fail

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security
#cgo CFLAGS: -Wall -Wextra -Wconversion -Wformat -Wformat-security -Werror
#cgo CFLAGS: -fstack-protector-strong -fstack-clash-protection -fno-common
#cgo CFLAGS: -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
#cgo LDFLAGS: -lpam -ljson-c
#cgo LDFLAGS: -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
#include "cgo_bridge.h"
*/
import "C"
