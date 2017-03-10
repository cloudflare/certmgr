package testutil

import "io/ioutil"

// TempName generates a new temporary file name. The caller should
// remove the temporary file when done.
func TempName() (string, error) {
	tmpf, err := ioutil.TempFile("", "transport_cachedkp_")
	if err != nil {
		return "", err
	}

	name := tmpf.Name()
	tmpf.Close()
	return name, nil
}
