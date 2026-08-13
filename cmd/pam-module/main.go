// Command pam-module produces oauth2_pam.so, the PAM module that talks to the
// oauth2-pam broker.
//
// The PAM entry points (pam_sm_authenticate and friends) are implemented in C
// in cgo_bridge_linux.c. cgo compiles that file into the shared object only
// because pam_linux.go, part of this package, imports "C" — an earlier layout
// kept the C sources in pkg/pam, which nothing imported, so the .so was built
// with no PAM entry points at all and PAM refused to load it.
//
// This main() is never called: the artifact is a c-shared library loaded by
// PAM, not an executable. It exists because a Go main package requires it, and
// it is deliberately in a file with no build constraint and no cgo so that
// `go build ./...` works on non-Linux systems, where Linux-PAM's headers do
// not exist.
package main

func main() {}
