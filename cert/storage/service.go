package storage

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// FileServiceOptions is for passing configurables for instantiating a service manager.
type FileServiceOptions struct {
	Action            string
	Service           string
	CheckTargetStatus bool
}

// FileServiceNotifier wraps a FileBackend and provides systemd/sysv/openrc/command type notifications
// so services know to reload PKI
type FileServiceNotifier struct {
	*FileBackend
	*FileServiceOptions
	subCommandIsLastArgument bool
	serviceBinary            string
	statusCommand            string
}

// SupportedServiceBackends is the list of init systems we support.
var SupportedServiceBackends = []string{
	"circus",
	"openrc",
	"systemd",
	"sysv",
}

// NewFileServiceNotifier returns a new storage backend that persists to FileBackend, and invokes
// service (systemd, rc5, etc) restart/reloads of targeted services
func NewFileServiceNotifier(FileBackend *FileBackend, name string, config *FileServiceOptions) (*FileServiceNotifier, error) {
	f := &FileServiceNotifier{
		FileBackend:        FileBackend,
		FileServiceOptions: config,
		statusCommand:      "status",
	}
	switch name {
	case "circus":
		f.serviceBinary = "circus"
	case "openrc":
		f.serviceBinary = "rc-service"
		f.subCommandIsLastArgument = true
	case "systemd":
		f.serviceBinary = "systemctl"
		f.statusCommand = "is-active"
	case "sysv":
		f.serviceBinary = "service"
		f.subCommandIsLastArgument = true
		f.statusCommand = ""
	default:
		return nil, fmt.Errorf("service backend %s isn't supported", name)
	}

	if config.Action != "reload" && config.Action != "restart" {
		return nil, fmt.Errorf("service backend '%s': action '%s' isn't valid, must be either 'restart' or 'reload'", name, config.Action)
	}
	if config.Service == "" {
		return nil, fmt.Errorf("service backend '%s': action '%s' specified, but service is empty", name, config.Action)
	}
	return f, nil
}

func (f *FileServiceNotifier) invoke(command string) error {
	var err error
	if f.subCommandIsLastArgument {
		err = runEnv(nil, f.serviceBinary, f.Service, command)
	} else {
		err = runEnv(nil, f.serviceBinary, command, f.Service)
	}
	return errors.WithMessagef(err, "invoking %s for %s", f.serviceBinary, command)
}

// Store persists the PKI content, and triggers actions if there are no errors.
func (f *FileServiceNotifier) Store(ca *x509.Certificate, keyPair *tls.Certificate) error {
	log := log.With().Str("service", f.Service).Logger()
	// store the content
	err := errors.WithMessage(
		f.FileBackend.Store(ca, keyPair),
		"while persisting PKI",
	)
	if err != nil {
		log.Debug().Msg("file service notifier- got error from storage, actions won't be ran")
		return err
	}

	// next trigger the relevant action.
	if f.CheckTargetStatus && f.statusCommand != "" {
		log.Debug().Msg("backend service supports status, invoking")
		err := f.invoke(f.statusCommand)
		log.Debug().Err(err).Msg("backend service status error")
		if err != nil {
			// yes, this is the way you have to do this.  It sucks.
			if exitErr, ok := errors.Cause(err).(*exec.ExitError); ok {
				// non zero exit code; log it.
				log.Info().Int("status_code", exitErr.Sys().(syscall.WaitStatus).ExitStatus()).Msg("backend service status non-zero; skipping action")
				return nil
			}
			return errors.WithMessagef(err, "status check for service '%s' failed", f.Service)
		}
		// no err means zero exit code.  Proceed.
	}

	log.Info().Str("action", f.Action).Msg("actioning service")

	return errors.WithMessagef(
		f.invoke(f.Action),
		"failed to %s service %s", f.Action, f.Service,
	)
}
