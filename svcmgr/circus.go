package svcmgr

import "github.com/cloudflare/cfssl/log"

/////////////////////////
// Circus integration. //
/////////////////////////
type circus struct{}

func (sm circus) RestartService(service string) error {
	log.Info("restarting service ", service)
	return run("circus", "restart", service)
}

func (sm circus) ReloadService(service string) error {
	log.Info("reloading service ", service)
	return run("circus", "reload", service)
}

func init() {
	supported["circus"] = circus{}
}
