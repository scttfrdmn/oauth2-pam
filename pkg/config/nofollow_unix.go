//go:build unix

package config

import "syscall"

// oNoFollow makes an open fail rather than follow a symlink at the last path
// component. There is no portable spelling of it in the os package, for the same
// reason fileOwner needs a build-tagged file: not every platform has it.
const oNoFollow = syscall.O_NOFOLLOW
