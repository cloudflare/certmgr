package cert

import (
	"encoding/json"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/errors"
	log "github.com/sirupsen/logrus"
)

// Utility functions for interacting with the transport package.

// authErrorHTTP builds the error code returned for an error.
var authErrorHTTP = int(errors.APIClientError) + int(errors.ClientHTTPError)

const authErrorMessage = "invalid token"

// isAuthError returns true if the error is due to a CFSSL
// authentication error.
func isAuthError(err error) bool {
	cferr, ok := err.(*errors.Error)
	if !ok {
		return false
	}

	if cferr.ErrorCode == authErrorHTTP {
		var response api.Response
		innerErr := json.Unmarshal([]byte(cferr.Message), &response)
		if innerErr != nil {
			return false
		}

		log.Debugf("manager: CFSSL error is %#v", cferr)
		for _, responseError := range response.Errors {
			if responseError.Message == authErrorMessage {
				return true
			}
		}
	}

	return false
}
