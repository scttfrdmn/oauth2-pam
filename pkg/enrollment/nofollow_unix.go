//go:build unix

package enrollment

import "syscall"

// oNoFollow makes an open fail rather than follow a symlink at the last path
// component. There is no portable spelling of it in the os package, for the same
// reason fileOwner needs a build-tagged file: not every platform has it.
//
// pkg/config has its own copy for its own secret files. The duplication is two
// lines, and the alternative is one of these packages importing the other for a
// constant — pkg/config cannot import this one, and this one importing pkg/config
// for a syscall flag would be worse than the copy.
const oNoFollow = syscall.O_NOFOLLOW
