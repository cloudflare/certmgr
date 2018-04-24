package svcmgr

import "github.com/cloudflare/cfssl/log"

///////////////////
// OpenRC support. //
///////////////////
type openrc struct{}

func (sm openrc) RestartService(service string) error {
	log.Info("restarting service ", service)
	return run("rc-service", service, "restart")
}

func (sm openrc) ReloadService(service string) error {
	log.Info("reloading service ", service)
	return run("rc-service", service, "reload")
}

func init() {
	supported["openrc"] = openrc{}
}
