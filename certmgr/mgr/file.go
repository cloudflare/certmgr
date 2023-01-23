package mgr

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/yaml.v2"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/cert/storage"
	"github.com/cloudflare/certmgr/cert/storage/util"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	log "github.com/sirupsen/logrus"
)

//validExtUsage extracts the valid values from cfssl's ExtKeyUsage map, which we print when someone specifies an invalid value
var validExtUsage = func() []string {
	usages := make([]string, 0, len(config.ExtKeyUsage))
	for usage := range config.ExtKeyUsage {
		usages = append(usages, usage)
	}
	sort.Strings(usages)
	return usages
}

// ParsableAuthority is an authority struct that can load the Authkey from content on disk.  This is used internally
// by Authority for unmarshal- this shouldn't be used for anything but on disk certmgr spec's.
type ParsableAuthority struct {
	cert.Authority `yaml:",inline"`

	// Name is an unused field; it was added in v1.4.0 to support loading a full Authority from certmgr config
	// but was never completed.
	Name string `json:"name" yaml:"name"`

	// AuthKeyFile, if specified, will result in reading the given pathway from the OS and using the
	// whitespace stripped content as the AuthKey.  This will override Authkey if both are specified.
	AuthKeyFile string `json:"auth_key_file" yaml:"auth_key_file"`

	// CA is for compatibility with old certmgr spec approach of intermixing CA with authority.
	CA *util.CertificateFile `json:"file" yaml:"file"`
}

// UnmarshalJSON unmarshal's a JSON representation of Authority object including supporting loading the authkey from
// a file on disk (thus do not unmarshall untrusted definitions).
func (pa *ParsableAuthority) UnmarshalJSON(data []byte) error {
	type alias ParsableAuthority
	var p alias
	if err := StrictJSONUnmarshal(data, &p); err != nil {
		return err
	}
	*pa = ParsableAuthority(p)
	return pa.loadFromDiskIfNeeded()
}

// UnmarshalYAML unmarshal's a YAML representation of Authority object including supporting loading the authkey from
// a file on disk (thus do not unmarshall untrusted definitions).
func (pa *ParsableAuthority) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type alias ParsableAuthority
	if err := unmarshal((*alias)(pa)); err != nil {
		return err
	}
	return pa.loadFromDiskIfNeeded()
}

func (pa *ParsableAuthority) loadFromDiskIfNeeded() error {
	if pa.AuthKeyFile == "" {
		return nil
	}
	log.Debugf("loading auth_key_file %v", pa.AuthKeyFile)
	content, err := ioutil.ReadFile(pa.AuthKeyFile)
	if err != nil {
		return fmt.Errorf("failed reading auth_key_file %v: %v", pa.AuthKeyFile, err)
	}
	pa.AuthKey = strings.TrimSpace(string(content))
	return nil
}

// ParsableSpecOptions is a struct used for unmarshalling a SpecOptions, suppressing
// unmarshall issues for durations.
type ParsableSpecOptions struct {
	cert.SpecOptions

	// This defines the service manager to use.  This should be defined
	// globally rather than per cert- it's allowed here to allow cert
	// definitions to use a servicemanager of 'command' to allow freeform
	// invocations.
	ServiceManagerName string `json:"svcmgr" yaml:"svcmgr"`

	// ServiceManagerTakeActionOnlyIfRunning if set to true, disables reload/restart attempts
	// if the target isn't running.  If the service manager service in use isn't a service manager- for example,
	// a raw command- this directive does nothing.
	ServiceManagerTakeActionOnlyIfRunning bool `json:"take_actions_only_if_running" yaml:"take_actions_only_if_running"`

	// ParsedBefore is used to update the SpecOptions.Before field.
	ParsedBefore ParsableDuration `json:"before" yaml:"before"`

	// ParsedInterval is used to update the SpecOptions.Interval field.
	ParsedInterval ParsableDuration `json:"interval" yaml:"interval"`

	// ParsedIntervalSplay is used to update the SpecOptions.IntervalSplay field.
	ParsedIntervalSplay ParsableDuration `json:"interval_splay" yaml:"interval_splay"`

	// ParsedInitialSplay is used to update the SpecOptions.InitialSplay field.
	ParsedInitialSplay ParsableDuration `json:"initial_splay" yaml:"initial_splay"`

	// ParsedKeyUsages is used to update the SpecOptions.KeyUsages field.
	ParsedKeyUsages []string `json:"key_usages" yaml:"key_usages"`

	// Remote is shorthand for updating CA.Remote for instantiation.
	// This specifies the remote upstream to talk to.
	Remote string `json:"remote" yaml:"remote"`
}

// FinalizeSpecOptionParsing backfills the embedded SpecOptions structure with values parsed during unmarshall'ing.
// This should be invoked before you pass SpecOptions to other consumers.
func (p *ParsableSpecOptions) FinalizeSpecOptionParsing() {
	if p.ParsedBefore != 0 {
		p.Before = time.Duration(p.ParsedBefore)
	}
	if p.ParsedInterval != 0 {
		p.Interval = time.Duration(p.ParsedInterval)
	}
	if p.ParsedIntervalSplay != 0 {
		p.IntervalSplay = time.Duration(p.ParsedIntervalSplay)
	}
	if p.ParsedInitialSplay != 0 {
		p.InitialSplay = time.Duration(p.ParsedInitialSplay)
	}
}

// A ParsableSpec is an intermediate struct representing a certmgr spec
// on disk; this is used for parsing and converted into a Spec
type ParsableSpec struct {
	ParsableSpecOptions `yaml:",inline"`

	// The service is the service that uses this certificate. If
	// this field is not empty, the action below will be applied
	// to this service upon certificate renewal. It can also be
	// used to describe what this certificate is for.
	Service string `json:"service" yaml:"service"`

	// Action is one of empty, "nop", "reload", or "restart" (see
	// the svcmgr package for details).
	Action string `json:"action" yaml:"action"`

	// Request contains the CSR metadata needed to request a
	// certificate.
	Request *csr.CertificateRequest `json:"request" yaml:"request"`

	// Key contains the file metadata for the private key.
	Key *util.File `json:"private_key" yaml:"private_key"`

	// Cert contains the file metadata for the certificate.
	Cert *util.CertificateFile `json:"certificate" yaml:"certificate"`

	CA *util.CertificateFile `json:"ca" yaml:"ca"`

	// CA specifies the certificate authority that should be used.
	Authority ParsableAuthority `json:"authority" yaml:"authority"`
}

// loadFromPath load and fill this spec from the given pathway
// If this invocation returns an error, the spec instance should be discarded
// and recreated.
func (spec *ParsableSpec) loadFromPath(path string) error {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	switch filepath.Ext(path) {
	case ".json":
		err = StrictJSONUnmarshal(in, &spec)
	case ".yml", ".yaml":
		err = yaml.UnmarshalStrict(in, &spec)
	default:
		err = fmt.Errorf("unrecognised spec file format")
	}

	return err
}

// ReadSpecFile reads a spec from a JSON configuration util.
func ReadSpecFile(path string, defaults *ParsableSpecOptions) (*cert.Spec, error) {
	var spec = &ParsableSpec{
		Request: csr.New(),
	}
	if defaults != nil {
		spec.ParsableSpecOptions = *defaults
	}
	if spec.Before == 0 {
		spec.Before = cert.DefaultBefore
	}
	if spec.Interval == 0 {
		spec.Interval = cert.DefaultInterval
	}

	err := spec.loadFromPath(path)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed reading %s", path)
	}

	specStat, err := os.Stat(path)
	if err != nil {
		// Hit the race; we read the file but someone wiped it.
		return nil, err
	}

	// transfer the parsed durations into their final resting spot.
	spec.FinalizeSpecOptionParsing()

	if len(spec.ParsedKeyUsages) > 0 {
		for _, KeyUsageRaw := range spec.ParsedKeyUsages {
			keyUsage, ok := config.ExtKeyUsage[strings.ToLower(KeyUsageRaw)]
			if !ok {
				return nil, fmt.Errorf("spec %s specifies unknown key usage '%s'. Valid values are: %q", path, KeyUsageRaw, validExtUsage())
			}
			spec.KeyUsages = append(spec.KeyUsages, keyUsage)
		}
	} else { // Key usage not defined, default to server auth as that is both most common and was our previous behavior.
		log.Warnf("spec %s does not specify key usage, defaulting to \"server auth\"", path)
		spec.KeyUsages = []x509.ExtKeyUsage{config.ExtKeyUsage["server auth"]}
	}

	if spec.Authority.Remote == "" {
		spec.Authority.Remote = spec.Remote
	}

	if spec.Authority.Remote == "" {
		return nil, errors.New("no remote specified in authority (either in the spec or in the certmgr config)")
	}

	if spec.Authority.CA != nil {
		if spec.CA != nil {
			return nil, errors.New("both deprecated authority:file field was specified and 'ca'.  Only one is tolerated (use 'ca')")
		}
		log.Warnf("spec %s has 'file' as part of authority field; this is deprecated in favor of a top level 'ca' field.", path)
		spec.CA = spec.Authority.CA
	}

	fb, err := storage.NewFileBackend(spec.CA, spec.Cert, spec.Key)
	if err != nil {
		return nil, err
	}

	var pkiStorage storage.PKIStorage
	if spec.ServiceManagerName == "" || spec.ServiceManagerName == "dummy" {
		log.Debugf("no notification backend configured for %s", path)
		pkiStorage = fb
	} else {
		if spec.ServiceManagerName == "command" {
			log.Debugf("creating command notifier for %s", path)
			if spec.Service != "" {
				return nil, fmt.Errorf("svcmgr backend of 'command' doesn't support the 'service' field; got %s", spec.Service)
			}
			pkiStorage, err = storage.NewFileCommandNotifier(fb, spec.Action)
			err = errors.WithMessage(err, "while instantiating command notifier")
		} else {
			log.Debugf("creating service notifier for %s", path)
			// assume it's sysv/systemd
			pkiStorage, err = storage.NewFileServiceNotifier(
				fb,
				spec.ServiceManagerName,
				&storage.FileServiceOptions{
					Action:            spec.Action,
					Service:           spec.Service,
					CheckTargetStatus: spec.ServiceManagerTakeActionOnlyIfRunning,
				},
			)
			err = errors.WithMessage(err, "while instantiating service notifier")
		}
	}
	if err != nil {
		return nil, err
	}

	s, err := cert.NewSpec(path, &spec.ParsableSpecOptions.SpecOptions, &spec.Authority.Authority, spec.Request, pkiStorage)
	if err != nil {
		return nil, err
	}

	s.WakeCallbacks = append(s.WakeCallbacks, func() {
		warnIfHasChangedOnDisk(path, specStat.ModTime())
	})
	return s, nil
}

// warnIfHasChangedOnDisk logs warnings if the spec in memory doesn't reflect what's on disk.
func warnIfHasChangedOnDisk(path string, loadTime time.Time) {
	specStat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warningf("spec %s was removed from on disk", path)
		} else {
			log.Warningf("spec %s failed to be checked on disk: %s", path, err)
		}
	} else if specStat.ModTime().After(loadTime) {
		log.Warningf("spec %s has changed on disk", path)
	} else {
		log.Debugf("spec %s hasn't changed on disk", path)
	}
}
