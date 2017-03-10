package logging

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

// A list of implementations that should be tested.
var implementations []Logger

func init() {
	lw := NewLogWriter(&bytes.Buffer{}, nil)
	cw := NewConsole()

	implementations = append(implementations, lw)
	implementations = append(implementations, cw)
}

func TestFileSetup(t *testing.T) {
	fw1, err := NewFile("fw1.log", true)
	if err != nil {
		t.Fatalf("failed to create new file logger: %v", err)
	}

	fw2, err := NewSplitFile("fw2.log", "fw2.err", true)
	if err != nil {
		t.Fatalf("failed to create new split file logger: %v", err)
	}

	implementations = append(implementations, fw1)
	implementations = append(implementations, fw2)
}

func TestImplementations(t *testing.T) {
	for _, l := range implementations {
		l.Info("TestImplementations", "Info message",
			map[string]string{"type": fmt.Sprintf("%T", l)})
		l.Warn("TestImplementations", "Warning message",
			map[string]string{"type": fmt.Sprintf("%T", l)})
	}
}

func TestCloseLoggers(t *testing.T) {
	for _, l := range implementations {
		l.Close()
	}
}

func TestDestroyLogFiles(t *testing.T) {
	os.Remove("fw1.log")
	os.Remove("fw2.log")
	os.Remove("fw2.err")
}
