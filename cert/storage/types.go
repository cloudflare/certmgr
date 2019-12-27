package storage

import (
	"crypto/tls"
	"crypto/x509"
)

// PKIStorage defines the interfaces that spec's use for loading PKI content, and storing it.
type PKIStorage interface {
	// Load asks the storage implementation to return the CA and keypair it has (if any),
	// returning an error if it failed to load what it expects on disk, or if things like
	// permissions were wrong.
	Load() (ca *x509.Certificate, keyPair *tls.Certificate, error error)

	// Store updates the storage implementation with the new CA/keypair.
	Store(ca *x509.Certificate, keyPair *tls.Certificate) error

	// Wipe directs the backend to remove any PKI it may have stored.
	Wipe() error

	// WantsKeyPair indicates if this backend stores a keypair- a certificate and key.  Some deployments
	// just wish to update for CA changes, and those deploys should return false here.
	WantsKeyPair() bool

	// GetPaths returns any paths this storage may manage; if it's in memory, then it's an empty slice.
	GetPaths() []string
}
