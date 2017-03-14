package svcmgr

/////////////////////
// No integration! //
/////////////////////
type dummy struct{}

func (dummy) RestartService(string) error {
	return nil
}

func (dummy) ReloadService(string) error {
	return nil
}

func init() {
	supported["dummy"] = dummy{}
}
