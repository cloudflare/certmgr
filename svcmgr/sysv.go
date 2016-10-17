package svcmgr

import "github.com/cloudflare/cfssl/log"

///////////////////
// SysV support. //
///////////////////
type sysv struct{}

func (sm sysv) RestartService(service string) error {
	log.Info("restarting service ", service)
	return run("service", service, "restart")
}

func (sm sysv) ReloadService(service string) error {
	log.Info("reloading service ", service)
	return run("service", service, "reload")
}

func init() {
	supported["sysv"] = sysv{}
}
