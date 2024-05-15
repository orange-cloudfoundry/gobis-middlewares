package oauth2

import (
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
)

const (
	Oauth2ClientKey MiddlewareOauth2ContextKey = iota
)

type MiddlewareOauth2ContextKey int

// setOauth2Client Set the username to a request context
func setOauth2Client(req *http.Request, oauth2Client *http.Client) {
	client := oauth2ClientPtr(req)
	if client == nil {
		gobis.AddContextValue(req, Oauth2ClientKey, oauth2Client)
		return
	}
}

// Oauth2Client Retrieve username from a request context
func Oauth2Client(req *http.Request) *http.Client {
	return oauth2ClientPtr(req)
}

func oauth2ClientPtr(req *http.Request) *http.Client {
	var client *http.Client
	gobis.InjectContextValue(req, Oauth2ClientKey, &client)
	return client
}
