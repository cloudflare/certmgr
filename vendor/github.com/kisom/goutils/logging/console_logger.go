package logging

import "os"

// Console is a Logger that writes to the console. It must be
// constructed with a call to NewConsole.
type Console struct {
	*LogWriter
}

// NewConsole returns a new console logger.
func NewConsole() *Console {
	return &Console{LogWriter: NewLogWriter(os.Stdout, os.Stderr)}
}
