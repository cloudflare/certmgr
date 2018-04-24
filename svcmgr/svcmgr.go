// Package svcmgr contains integration for managing services on a
// machine.
//
// Currently supported service managers are systemd, circus, sysv,
// openrc, and dummy.
package svcmgr

import (
	"fmt"
	"os/exec"

	"github.com/cloudflare/cfssl/log"
)

var supported = map[string]Manager{}

// The Manager interface provides a common API for interacting with
// service managers.
type Manager interface {
	RestartService(service string) error
	ReloadService(service string) error
}

func run(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)

	log.Debugf("running '%s %v'", prog, args)
	return cmd.Run()
}

// New returns a new service manager.
func New(name string) (Manager, error) {
	sm, ok := supported[name]
	if !ok {
		return nil, fmt.Errorf("svcmgr: unsupported service manager '%s'", name)
	}

	return sm, nil
}
