package mgr

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// This file provides functionality for working around JSON issues in our reading of configs.

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

// StrictJSONUnmarshal unmarshals a byte source into the given interface while also
// enforcing that there is no unknown fields
func StrictJSONUnmarshal(data []byte, object interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err := dec.Decode(object)
	if err != nil {
		return err
	}
	if dec.More() {
		return errors.New("multiple json objects found, only one is allowed")
	}
	return nil
}
