//go:build !unix

package enrollment

import "io/fs"

// fileOwner cannot determine ownership on this platform and says so rather than
// guessing. A false "owned by root" would turn the ownership half of
// checkPerms into a rubber stamp; the permission-bit half still applies.
func fileOwner(_ fs.FileInfo) (uint32, bool) { return 0, false }
