package logging

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Logger provides a standardised logging interface.
type Logger interface {
	// SetLevel sets the minimum log level.
	SetLevel(Level)

	// Good returns true if the Logger is healthy.
	Good() bool

	// Status returns an error corresponding to the logger's state;
	// if it's healthy (e.g. Good() returns true), Error will
	// return nil.
	Status() error

	// Close gives the Logger the opportunity to perform any cleanup.
	Close()

	// Log messages consist of four components:
	//
	// 1. The **level** attaches a notion of priority to the log message.
	//    Several log levels are available:
	//
	//    + FATAL (32): the system is in an unsuable state, and cannot
	//      continue to run. Most of the logging for this will cause the
	//      program to exit with an error code.
	//    + CRITICAL (16): critical conditions. The error, if uncorrected, is
	//      likely to cause a fatal condition shortly.  An example is running
	//      out of disk space. This is something that the ops team should get
	//      paged for.
	//    + ERROR (8): error conditions. A single error doesn't require an
	//      ops team to be paged, but repeated errors should often trigger a
	//      page based on threshold triggers. An example is a network
	//      failure: it might be a transient failure (these do happen), but
	//      most of the time it's self-correcting.
	//    + WARNING (4): warning conditions. An example of this is a bad
	//      request sent to a server. This isn't an error on the part of the
	//      program, but it may be indicative of other things. Like errors,
	//      the ops team shouldn't be paged for errors, but a page might be
	//      triggered if a certain threshold of warnings is reached (which is
	//      typically much higher than errors). For example, repeated
	//      warnings might be a sign that the system is under attack.
	//    + INFO (2): informational message. This is a normal log message
	//      that is used to deliver information, such as recording
	//      requests. Ops teams are never paged for informational
	//      messages. This is the default log level.
	//    + DEBUG (1): debug-level message. These are only used during
	//      development or if a deployed system repeatedly sees abnormal
	//      errors.
	//
	//    The numeric values indicate the priority of a given level.
	//
	// 2. The **actor** is used to specify which component is generating
	//    the log message. This could be the program name, or it could be
	//    a specific component inside the system.
	//
	// 3. The **event** is a short message indicating what happened. This is
	//    most like the traditional log message.
	//
	// 4. The **attributes** are an optional set of key-value string pairs that
	//    provide additional information.
	//
	// Additionally, each log message has an associated timestamp. For the
	// text-based logs, this is "%FT%T%z"; for the binary logs, this is a
	// 64-bit Unix timestamp. An example text-based timestamp might look like ::
	//
	//   [2016-03-27T20:59:27-0700] [INFO] [actor:server event:request received] client=192.168.2.5 request-size=839
	//
	// Note that this is organised in a manner that facilitates parsing::
	//
	//   /\[(\d{4}-\d{3}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\] \[(\w+\)]\) \[actor:(.+?) event:(.+?)\]/
	//
	// will cover the header:
	//
	// + ``$1`` contains the timestamp
	// + ``$2`` contains the level
	// + ``$3`` contains the actor
	// + ``$4`` contains the event
	Debug(actor, event string, attrs map[string]string)
	Info(actor, event string, attrs map[string]string)
	Warn(actor, event string, attrs map[string]string)
	Error(actor, event string, attrs map[string]string)
	Critical(actor, event string, attrs map[string]string)
	Fatal(actor, event string, attrs map[string]string)
	FatalCode(exitcode int, actor, event string, attrs map[string]string)
	FatalNoDie(actor, event string, attrs map[string]string)
}

// A LogWriter is a Logger that operates on an io.Writer.
type LogWriter struct {
	wo, we io.Writer
	lvl    Level
	state  error
	snl    bool // suppress newline
}

// NewLogWriter takes an output writer (wo) and an error writer (we),
// and produces a new Logger. If the error writer is nil, error logs
// will be multiplexed onto the output writer.
func NewLogWriter(wo, we io.Writer) *LogWriter {
	if we == nil {
		we = wo
	}

	return &LogWriter{
		wo:    wo,
		we:    we,
		lvl:   DefaultLevel,
		state: nil,
	}
}

func (lw *LogWriter) output(w io.Writer, lvl Level, actor, event string, attrs map[string]string) {
	t := time.Now().Format(DateFormat)
	fmt.Fprintf(w, "[%s] [%s] [actor:%s event:%s]", t, levelPrefix[lvl], actor, event)
	for k, v := range attrs {
		fmt.Fprintf(w, " %s=%s", k, v)
	}

	if !lw.snl {
		fmt.Fprintf(w, "\n")
	}
}

// Debug emits a debug-level message. These are only used during
// development or if a deployed system repeatedly sees abnormal
// errors.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) Debug(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelDebug {
		return
	}
	lw.output(lw.wo, LevelDebug, actor, event, attrs)
}

// Info emits an informational message. This is a normal log message
// that is used to deliver information, such as recording
// requests. Ops teams are never paged for informational
// messages. This is the default log level.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) Info(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelInfo {
		return
	}
	lw.output(lw.wo, LevelInfo, actor, event, attrs)
}

// Warn emits a warning message. An example of this is a bad request
// sent to a server. This isn't an error on the part of the program,
// but it may be indicative of other things. Like errors, the ops team
// shouldn't be paged for errors, but a page might be triggered if a
// certain threshold of warnings is reached (which is typically much
// higher than errors). For example, repeated warnings might be a sign
// that the system is under attack.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) Warn(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelWarning {
		return
	}
	lw.output(lw.we, LevelWarning, actor, event, attrs)
}

// Error emits an error message. A single error doesn't require an ops
// team to be paged, but repeated errors should often trigger a page
// based on threshold triggers. An example is a network failure: it
// might be a transient failure (these do happen), but most of the
// time it's self-correcting.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) Error(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelError {
		return
	}
	lw.output(lw.we, LevelError, actor, event, attrs)
}

// Critical emits a message indicating a critical condition. The
// error, if uncorrected, is likely to cause a fatal condition
// shortly.  An example is running out of disk space. This is
// something that the ops team should get paged for.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) Critical(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelCritical {
		return
	}
	lw.output(lw.we, LevelCritical, actor, event, attrs)
}

// Fatal emits a message indicating that the system is in an unsuable
// state, and cannot continue to run. The program will exit with exit
// code 1.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) Fatal(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelFatal {
		return
	}
	lw.output(lw.we, LevelFatal, actor, event, attrs)
	os.Exit(1)
}

// Fatal emits a message indicating that the system is in an unsuable
// state, and cannot continue to run. The program will exit with the
// exit code speicfied in the exitcode argument.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) FatalCode(exitcode int, actor, event string, attrs map[string]string) {
	if lw.lvl > LevelFatal {
		return
	}
	lw.output(lw.we, LevelFatal, actor, event, attrs)
	os.Exit(exitcode)
}

// Fatal emits a message indicating that the system is in an unsuable
// state, and cannot continue to run. The program will not exit; it is
// assumed that the caller has some final clean up to perform.
//
// Actor specifies the component emitting the message; event indicates
// the event that caused the log message to be emitted. attrs is a map
// of key-value string pairs that can be used to provide additional
// information.
func (lw *LogWriter) FatalNoDie(actor, event string, attrs map[string]string) {
	if lw.lvl > LevelFatal {
		return
	}
	lw.output(lw.we, LevelFatal, actor, event, attrs)
}

// Good returns true if the logger is healthy.
func (lw *LogWriter) Good() bool {
	return lw.state == nil
}

// Status returns an error value from the logger if it isn't healthy,
// or nil if the logger is healthy.
func (lw *LogWriter) Status() error {
	return lw.state
}

// SetLevel changes the log level.
func (lw *LogWriter) SetLevel(l Level) {
	lw.lvl = l
}

// Close is a no-op that satisfies the Logger interface.
func (lw *LogWriter) Close() {}
