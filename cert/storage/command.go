package storage

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	shellBinary    string
	canCheckSyntax bool
)

// runEnv is used for logging commands invoked.  All storage invocations should use this.
func runEnv(env *map[string]string, prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Env = append(os.Environ())
	if env != nil {
		for key, val := range *env {
			cmd.Env = append(cmd.Env, key+"="+val)
		}
	}
	log.Debug().Str("exec", prog).Strs("args", args).Msg("executing command")
	return cmd.Run()
}

// FileCommandNotifier creates a new storage backend that persists to disk (FileBackend), while also invoking
// a freeform shell command if the persistence succeeded.
type FileCommandNotifier struct {
	*FileBackend
	command string
}

// NewFileCommandNotifier creates a new storage backend; it expects a FileBackend for the content to store,
// and a command (in string form) for what to execute on successful updates.
func NewFileCommandNotifier(FileBackend *FileBackend, command string) (*FileCommandNotifier, error) {
	if canCheckSyntax {
		log.Debug().Str("cmd", command).Str("svcmgr", "command").Msg("svcmgr: validating the action definition ")
		err := runEnv(nil, shellBinary, "-n", "-c", command)
		if err != nil {
			return nil, errors.WithMessagef(err, "action %s failed bash -nc parse checks", command)
		}
	} else {
		log.Warn().Str("cmd", command).Str("svcmgr", "command").Msg("svcmgr: skipping parse check for command since bash couldn't be found")
	}
	return &FileCommandNotifier{
		FileBackend: FileBackend,
		command:     command,
	}, nil
}

// Store persists the PKI content, and triggers actions if there are no errors.
func (f *FileCommandNotifier) Store(ca *x509.Certificate, keyPair *tls.Certificate) error {
	err := errors.WithMessage(
		f.FileBackend.Store(ca, keyPair),
		"while persisting to disk",
	)
	if err != nil {
		return err
	}

	env := map[string]string{
		"CERTMGR_CA_PATH":   "",
		"CERTMGR_CERT_PATH": "",
		"CERTMGR_KEY_PATH":  "",
	}

	if f.FileBackend.ca != nil {
		env["CERTMGR_CA_PATH"] = f.FileBackend.ca.Path
	}
	if f.WantsKeyPair() {
		env["CERTMGR_CERT_PATH"] = f.FileBackend.cert.Path
		env["CERTMGR_KEY_PATH"] = f.FileBackend.key.Path
	}
	log.Info().Str("cmd", f.command).Str("svcmgr", "command").Msg("invoking command notification")
	return errors.WithMessage(
		runEnv(&env, shellBinary, "-c", f.command),
		"PKI was persisted, but command notification failed",
	)
}

func init() {
	// prefer bash if we can find it since it allows us to validate
	var err error
	shellBinary, err = exec.LookPath("bash")
	canCheckSyntax = true
	if err != nil {
		log.Info().Err(err).Str("svcmgr", "command").Msg("svcmgr couldn't find a bash binary; action statements will not be able to be validated for syntax")
		shellBinary, err = exec.LookPath("sh")
		if err != nil {
			log.Error().Str("svcmgr", "command").Msg("svcmgr 'command' is unavailable due to both bash and sh not being found in PATH")
			return
		}
		canCheckSyntax = false
	}
}
