//go:build windows

package reproit

import "os"

func sameSubjectFileVersion(before os.FileInfo, after os.FileInfo) bool {
	return os.SameFile(before, after)
}
