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

type managerCreator func(action string, service string) (Manager, error)

var SupportedBackends = map[string]managerCreator{}

// This defines the list of actions that the manager supports taking
// on a service whose certificate has been updated.
var defaultValidActions = map[string]bool{
	"restart": true,
	"reload":  true,
}

// The Manager interface provides a common API for interacting with
// service managers.
type Manager interface {
	TakeAction() error
}

func run(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	log.Debugf("running '%s %v'", prog, args)
	return cmd.Run()
}

// New returns a new service manager.
func New(name string, action string, service string) (Manager, error) {
	// if action is nop, then just return dummy.
	if action == "nop" {
		name = "dummy"
	}
	sm_func, ok := SupportedBackends[name]
	if !ok {
		return nil, fmt.Errorf("svcmgr: unsupported service manager '%s'", name)
	}

	manager, err := sm_func(action, service)
	return manager, err
}

type simpleManager struct {
	action_is_last bool
	binary         string
	action         string
	service        string
}

func (sm simpleManager) TakeAction() error {
	log.Infof("%ving service %v", sm.action, sm.service)
	if sm.action_is_last {
		return run(sm.binary, sm.service, sm.action)
	}
	err := run(sm.binary, sm.action, sm.service)
	if err != nil {
		err = fmt.Errorf("failed to %s service %s (err=%s)", sm.action, sm.service, err)
	}
	return err
}

func registerSimpleManager(binary string, action_is_last bool) managerCreator {
	return func(action string, service string) (Manager, error) {
		if !defaultValidActions[action] {
			return nil, fmt.Errorf("svcmgr: action '%s' is not supported by manager %s", action, binary)
		} else if service == "" {
			return nil, fmt.Errorf("svcmgr: manager '%s': action '%s' specified, but service is empty", binary, action)
		}
		return &simpleManager{
			binary:         binary,
			action:         action,
			service:        service,
			action_is_last: action_is_last,
		}, nil
	}
}

type dummyManager struct{}

func (dummyManager) TakeAction() error {
	return nil
}
func newDummyManager(action string, service string) (Manager, error) {
	return &dummyManager{}, nil
}

func init() {
	SupportedBackends["circus"] = registerSimpleManager("circus", false)
	SupportedBackends["openrc"] = registerSimpleManager("rc-service", true)
	SupportedBackends["systemd"] = registerSimpleManager("systemctl", false)
	SupportedBackends["sysv"] = registerSimpleManager("service", true)
	SupportedBackends["dummy"] = newDummyManager
}
