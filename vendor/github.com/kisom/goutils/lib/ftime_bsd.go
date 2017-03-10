// +build freebsd darwin netbsd

package lib

import (
	"time"

	"golang.org/x/sys/unix"
)

// FileTime contains the changed, modified, and accessed timestamps
// for a file.
type FileTime struct {
	Changed  time.Time
	Modified time.Time
	Accessed time.Time
}

func timeSpecToTime(ts unix.Timespec) time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

// LoadFileTime returns a FileTime associated with the file.
func LoadFileTime(path string) (FileTime, error) {
	var ft = FileTime{}
	var st = unix.Stat_t{}

	err := unix.Stat(path, &st)
	if err != nil {
		return ft, err
	}

	ft.Changed = timeSpecToTime(st.Ctimespec)
	ft.Modified = timeSpecToTime(st.Mtimespec)
	ft.Accessed = timeSpecToTime(st.Atimespec)
	return ft, nil
}
