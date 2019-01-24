package svcmgr

import (
	"fmt"
	"os/exec"

	"github.com/cloudflare/cfssl/log"
)

var (
	shellBinary    string
	canCheckSyntax bool
)

type commandManager struct {
	command string
}

func (cm commandManager) TakeAction(change_type string, spec_path string, ca_path string, cert_path string, key_path string) error {
	env := []string{
		"CERTMGR_CA_PATH=" + ca_path,
		"CERTMGR_CERT_PATH=" + cert_path,
		"CERTMGR_KEY_PATH=" + key_path,
		"CERTMGR_SPEC_PATH=" + spec_path,
		"CERTMGR_CHANGE_TYPE=" + change_type,
	}
	return runEnv(env, shellBinary, "-c", cm.command)
}

func newCommandManager(action string, service string) (Manager, error) {
	if service != "" {
		log.Warningf("svcmgr 'command': service '%s' for action '%s' doesn't do anything, ignoring", service, action)
	}
	if canCheckSyntax {
		log.Debugf("svcmgr 'command': validating the action definition %s", action)
		err := run(shellBinary, "-n", "-c", action)
		if err != nil {
			return nil, fmt.Errorf("svcmgr 'command': action '%s' failed bash -n -c parse checks: %s", action, err)
		}
	} else {
		log.Warningf("svcmgr 'command': skipping parse check for '%s' since bash couldn't be found", action)
	}
	return &commandManager{
		command: action,
	}, nil
}

func init() {
	// prefer bash if we can find it since it allows us to validate
	var err error
	shellBinary, err = exec.LookPath("bash")
	canCheckSyntax = true
	if err != nil {
		log.Infof("svcmgr 'command' couldn't find a bash binary; action statements will not be able to be validated for syntax: err %s", err)
		shellBinary, err = exec.LookPath("sh")
		if err != nil {
			log.Error("svcmgr 'command' is unavailable due to both bash and sh not being found in PATH")
			return
		}
		canCheckSyntax = false
	}
	SupportedBackends["command"] = newCommandManager
}
