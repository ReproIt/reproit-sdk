//go:build unix

package reproit

import (
	"os"
	"syscall"
)

func sameSubjectFileVersion(before os.FileInfo, after os.FileInfo) bool {
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return beforeOK && afterOK &&
		beforeStat.Ino == afterStat.Ino && beforeStat.Dev == afterStat.Dev
}
