package util

import (
	"encoding/json"
	"time"
)

// ParsableDuration is a custom type to provide time.Duration unmarshalling.
type ParsableDuration time.Duration

// UnmarshalJSON unmarshall's a JSON string into a time.Duration
func (d *ParsableDuration) UnmarshalJSON(data []byte) error {
	// note: yaml.v3 won't support ints, so neither will we.
	var err error
	var val string
	if err = json.Unmarshal(data, &val); err != nil {
		return err
	}
	temp, err := time.ParseDuration(val)
	if err != nil {
		*d = (ParsableDuration)(temp)
	}

	return err
}
