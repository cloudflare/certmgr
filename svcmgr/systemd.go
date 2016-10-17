package svcmgr

import "github.com/cloudflare/cfssl/log"

///////////////////////////
// Systemd integration. //
//////////////////////////
type systemd struct{}

func (sm systemd) RestartService(service string) error {
	log.Info("restarting service ", service)
	return run("systemctl", "restart", service)
}

func (sm systemd) ReloadService(service string) error {
	log.Info("reloading service ", service)
	return run("systemctl", "reload", service)
}

func init() {
	supported["systemd"] = systemd{}
}
