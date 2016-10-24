package cert

import "time"

// A List is a list of certificates sorted by next expiring.
type List []*Spec

// Len is the number of certificates in the list.
func (cl List) Len() int {
	return len(cl)
}

// Less reports whether the element with index i should sort before
// the element with index j.
func (cl List) Less(i, j int) bool {
	var expA, expB time.Time

	certA := cl[i].Certificate()
	if certA != nil {
		expA = certA.NotAfter
	}

	certB := cl[j].Certificate()
	if certB != nil {
		expB = certB.NotAfter
	}

	return expA.Before(expB)
}

// Swap swaps the elements with indexes i and j.
func (cl List) Swap(i, j int) {
	cl[i], cl[j] = cl[j], cl[i]
}
