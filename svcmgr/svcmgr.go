// Package svcmgr contains integration for managing services on a
// machine.
//
// Currently supported service managers are systemd, circus, sysv,
// openrc, and dummy.
package svcmgr

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// SupportedBackends map of 'backend' -> creator function.
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
	TakeAction(changeType string, specPath string, caPath string, certPath string, keyPath string) error
}

func runEnv(env []string, prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Env = append(os.Environ(), env...)
	log.Debugf("running '%s %v'", prog, args)
	return cmd.Run()
}

// Options is for passing configurables for instantiating a service manager.
type Options struct {
	Action            string
	Service           string
	CheckTargetStatus bool
}

// New returns a new service manager.
func New(name string, config *Options) (Manager, error) {
	// if action is nop, then just return dummy.
	if config.Action == "nop" {
		name = "dummy"
	}
	smFunc, ok := SupportedBackends[name]
	if !ok {
		return nil, fmt.Errorf("svcmgr: unsupported service manager '%s'", name)
	}

	manager, err := smFunc(config)
	if err != nil && config.Action == "" && config.Service == "" {
		return nil, errors.WithMessage(err, "failed to instantiate due to empty action/service; perhaps you meant to use the 'dummy' service manager?")
	}
	return manager, err
}

type simpleManager struct {
	*Options
	subCommandIsLastArgument bool
	serviceBinary            string
	statusCommand            string
}

func (sm simpleManager) invoke(env []string, subcommand string) error {
	if sm.subCommandIsLastArgument {
		return runEnv(env, sm.serviceBinary, sm.Service, subcommand)
	}
	return runEnv(env, sm.serviceBinary, subcommand, sm.Service)
}

func (sm simpleManager) TakeAction(string, string, string, string, string) error {
	if sm.CheckTargetStatus && sm.statusCommand != "" {
		err := sm.invoke([]string{}, sm.statusCommand)
		if err != nil {
			// yes, this is the way you have to do this.  It sucks.
			if exitErr, ok := err.(*exec.ExitError); ok {
				// non zero exit code; log it.
				log.Infof("status of service %v was non-zero: %v, skipping action", sm.Service, exitErr.Sys().(syscall.WaitStatus).ExitStatus())
				return nil
			}
			return errors.WithMessagef(err, "status check for service %s failed", sm.Service)
		}
		// no err means zero exit code.  Proceed.
	}
	log.Infof("%ving service %v", sm.Action, sm.Service)
	// service managers don't care what changed, just that we invoke them- thus no env.
	err := sm.invoke([]string{}, sm.Action)
	if err != nil {
		err = errors.WithMessagef(err, "failed to %s service %s", sm.Action, sm.Service)
	}
	return err
}

type managerCreator func(*Options) (Manager, error)

func registerSimpleManager(binary string, status string, subCommandIsLastArgument bool) managerCreator {
	return func(config *Options) (Manager, error) {
		if !defaultValidActions[config.Action] {
			return nil, fmt.Errorf("svcmgr: action '%s' is not supported by manager %s", config.Action, binary)
		} else if config.Service == "" {
			return nil, fmt.Errorf("svcmgr: manager '%s': action '%s' specified, but service is empty", binary, config.Action)
		}
		return &simpleManager{
			serviceBinary:            binary,
			statusCommand:            status,
			subCommandIsLastArgument: subCommandIsLastArgument,
			Options:                  config,
		}, nil
	}
}

type dummyManager struct{}

func (dummyManager) TakeAction(string, string, string, string, string) error {
	return nil
}
func newDummyManager(*Options) (Manager, error) {
	return &dummyManager{}, nil
}

func init() {
	SupportedBackends["circus"] = registerSimpleManager("circus", "status", false)
	SupportedBackends["openrc"] = registerSimpleManager("rc-service", "status", true)
	SupportedBackends["systemd"] = registerSimpleManager("systemctl", "is-active", false)
	SupportedBackends["sysv"] = registerSimpleManager("service", "", true)
	SupportedBackends["dummy"] = newDummyManager
}
