package cert

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"regexp"
	"strconv"

	"github.com/cloudflare/cfssl/log"
)

var idRegexp = regexp.MustCompile(`^\d+$`)

// Path sanitized string path
type Path string

// File contains path and ownership information for a file.
type File struct {
	Path  string `json:"path" yaml:"path"`
	Owner string `json:"owner" yaml:"owner"`
	Group string `json:"group" yaml:"group"`
	Mode  string `json:"mode" yaml:"mode"`

	uid, gid int
	mode     os.FileMode
}

// UnmarshalYAML implement yaml unmarshalling logic
func (f *File) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias File
	if err := unmarshal((*alias)(f)); err != nil {
		return err
	}
	return f.parse()
}

// UnmarshalJSON implement yaml unmarshalling logic
func (f *File) UnmarshalJSON(data []byte) error {
	type alias File
	if err := json.Unmarshal(data, (*alias)(f)); err != nil {
		return err
	}
	return f.parse()
}

// Parse sets up the File structure from its string parameters; the
// hint is used to provide a hint as to what file is being processed
// for use in error messages. This includes validating that the user
// and group referenced exist; providing sensible defaults, and
// processing the mode. The method is intended to allow set up after
// unmarshalling from a configuration file.
func (f *File) parse() (err error) {
	if f.Path == "" {
		return errors.New("missing path")
	}

	if f.Mode == "" {
		f.Mode = "0644"
	}

	var u *user.User
	if f.Owner == "" || f.Group == "" {
		u, err = user.Current()
		if err != nil {
			return err
		}

		if f.Owner == "" {
			f.Owner = u.Uid
		}

		if f.Group == "" {
			f.Group = u.Gid
		}
	}

	if idRegexp.MatchString(f.Owner) {
		f.uid, err = strconv.Atoi(f.Owner)
		if err != nil {
			return err
		}
	} else {
		if u == nil {
			u, err = user.Lookup(f.Owner)
			if err != nil {
				return err
			}

			f.uid, err = strconv.Atoi(u.Uid)
			if err != nil {
				return err
			}
		}
	}

	if idRegexp.MatchString(f.Group) {
		f.gid, err = strconv.Atoi(f.Group)
		if err != nil {
			return err
		}
	} else {
		var g *user.Group
		g, err = user.LookupGroup(f.Group)
		if err != nil {
			return err
		}

		f.gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return err
		}
	}

	mode, err := strconv.ParseUint(f.Mode, 0, 32)
	if err != nil {
		return err
	}

	f.mode = os.FileMode(mode)
	return nil
}

// Set ensures the file has the right owner/group and mode.
func (f *File) setPermissions() error {
	st, err := os.Stat(f.Path)
	if err != nil {
		return err
	}

	err = os.Chown(f.Path, f.uid, f.gid)
	if err != nil {
		return err
	}

	if st.Mode() != f.mode {
		err = os.Chmod(f.Path, f.mode)
		if err != nil {
			return err
		}
	}

	return nil
}

// Unlink deletes the file specified by the Path field.
func (f *File) Unlink() error {
	log.Debugf("removing %s", f.Path)
	err := os.Remove(f.Path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
