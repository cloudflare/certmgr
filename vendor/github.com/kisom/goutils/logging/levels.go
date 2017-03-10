package logging

// A Level represents a logging level.
type Level uint8

// The following constants represent logging levels in increasing levels of seriousness.
const (
	// LevelDebug are debug output useful during program testing
	// and debugging.
	LevelDebug = 1 << iota

	// LevelInfo is used for informational messages.
	LevelInfo

	// LevelWarning is for messages that are warning conditions:
	// they're not indicative of a failure, but of a situation
	// that may lead to a failure later.
	LevelWarning

	// LevelError is for messages indicating an error of some
	// kind.
	LevelError

	// LevelCritical are messages for critical conditions.
	LevelCritical

	// LevelFatal messages are akin to syslog's LOG_EMERG: the
	// system is unusable and cannot continue execution.
	LevelFatal
)

const DefaultLevel = LevelInfo

// Cheap integer to fixed-width decimal ASCII.  Give a negative width
// to avoid zero-padding. (From log/log.go in the standard library).
func itoa(i int, wid int) string {
	// Assemble decimal in reverse order.
	var b [20]byte
	bp := len(b) - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		b[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	b[bp] = byte('0' + i)
	return string(b[bp:])
}

func writeToOut(level Level) bool {
	if level < LevelWarning {
		return true
	}
	return false
}

var levelPrefix = [...]string{
	LevelDebug:    "DEBUG",
	LevelInfo:     "INFO",
	LevelWarning:  "WARNING",
	LevelError:    "ERROR",
	LevelCritical: "CRITICAL",
	LevelFatal:    "FATAL",
}

// DateFormat contains the default date format string used by the logger.
const DateFormat = "2006-01-02T15:03:04-0700"
