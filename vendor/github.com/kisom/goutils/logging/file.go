package logging

import "os"

// File writes its logs to file.
type File struct {
	fo, fe *os.File
	*LogWriter
}

func (fl *File) Close() {
	fl.fo.Close()
	if fl.fe != nil {
		fl.fe.Close()
	}
}

// NewFile creates a new Logger that writes all logs to the file
// specified by path. If overwrite is specified, the log file will be
// truncated before writing. Otherwise, the log file will be appended
// to.
func NewFile(path string, overwrite bool) (*File, error) {
	fl := new(File)

	var err error

	if overwrite {
		fl.fo, err = os.Create(path)
	} else {
		fl.fo, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	}

	if err != nil {
		return nil, err
	}

	fl.LogWriter = NewLogWriter(fl.fo, fl.fo)
	return fl, nil
}

// NewSplitFile creates a new Logger that writes debug and information
// messages to the output file, and warning and higher messages to the
// error file. If overwrite is specified, the log files will be
// truncated before writing.
func NewSplitFile(outpath, errpath string, overwrite bool) (*File, error) {
	fl := new(File)

	var err error

	if overwrite {
		fl.fo, err = os.Create(outpath)
	} else {
		fl.fo, err = os.OpenFile(outpath, os.O_WRONLY|os.O_APPEND, 0644)
	}

	if err != nil {
		return nil, err
	}

	if overwrite {
		fl.fe, err = os.Create(errpath)
	} else {
		fl.fe, err = os.OpenFile(errpath, os.O_WRONLY|os.O_APPEND, 0644)
	}

	if err != nil {
		fl.Close()
		return nil, err
	}

	fl.LogWriter = NewLogWriter(fl.fo, fl.fe)
	return fl, nil
}
