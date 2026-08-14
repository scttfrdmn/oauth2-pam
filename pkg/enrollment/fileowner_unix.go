//go:build unix

package enrollment

import (
	"io/fs"
	"syscall"
)

// fileOwner reports the uid owning info. The Stat_t assertion is the only way to
// ask: io/fs deliberately does not model ownership, because not every filesystem
// has it.
func fileOwner(info fs.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
