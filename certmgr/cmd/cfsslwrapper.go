package cmd

import "github.com/rs/zerolog/log"

// cfsslLogAdaptor implements SyslogWriter interface, redirecting to zerolog logging.
type cfsslLogAdaptor struct{}

func (cfssl *cfsslLogAdaptor) Debug(s string) {
	log.Debug().Msg(s)
}

func (cfssl *cfsslLogAdaptor) Info(s string) {
	log.Info().Msg(s)
}

func (cfssl *cfsslLogAdaptor) Warning(s string) {
	log.Warn().Msg(s)
}

func (cfssl *cfsslLogAdaptor) Err(s string) {
	log.Error().Msg(s)
}

func (cfssl *cfsslLogAdaptor) Crit(s string) {
	log.Error().Msg(s)
}

func (cfssl *cfsslLogAdaptor) Emerg(s string) {
	log.Error().Msg(s)
}
