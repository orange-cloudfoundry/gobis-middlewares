# Go-auth-pubtkt [![Build Status](https://travis-ci.org/orange-cloudfoundry/go-auth-pubtkt.svg?branch=master)](https://travis-ci.org/orange-cloudfoundry/go-auth-pubtkt)

This A golang implementation of [mod_auth_pubtkt](https://neon1.net/mod_auth_pubtkt/) with some enhancements 
(cookie encryption, optional check options ..)

## Usage

This can be used in two different ways:
- As a middleware
- As a lib (redirect will not be used, it will only check ticket)

### As a middleware

```go
package main

import (
        "net/http"
        "github.com/orange-cloudfoundry/go-auth-pubtkt"
)

func main() {
    finalHandler := http.HandlerFunc(func(w http.ResponseWriter, req http.Request){
        w.WriteHeader(200)
       
        ticket := pubtkt.TicketRequest(req)
        w.Write([]byte("you are logged as "+ ticket.Uid))
    })
    pubtktHandler, err := pubtkt.NewAuthPubTktHandler(pubtkt.AuthPubTktOptions{
        TKTAuthPublicKey: "mypublic key",
    }, finalHandler)
    // you can also see handler option in https://github.com/orange-cloudfoundry/go-auth-pubtkt/blob/master/middleware.go#L171-L203
    if err != nil {
        panic(err)
    }
    http.HandleFunc("/", pubtktHandler)
    http.ListenAndServe(":8080", nil)
}
```

### As a lib

```go
package main

import (
        "github.com/orange-cloudfoundry/go-auth-pubtkt"
)

func main() {
    auth, err := pubtkt.NewAuthPubTkt(pubtkt.AuthPubTktOptions{
        TKTAuthPublicKey: "mypublic key",
        TKTAuthCookieName: "auth_pubtkt",
        TKTAuthHeader: []string{"Cookie"},
    })
    if err != nil {
        panic(err)
    }
    err = auth.VerifyTicket(&pubtkt.Ticket{ 
        Uid: "myuser",
        Sig: "the_signature",
    }, "")
    if err != nil {
        panic(err)
    }
    // if no error we can continue
    // you can also use
    // Verify ticket and pre-check from a request
    // VerifyFromRequest(*http.Request) (*Ticket, error)
    // Transform a request to a ticket (if found)
    // RequestToTicket(*http.Request) (*Ticket, error)
    // Transform an encoded ticket or plain ticket as a ticket strcture
    // RawToTicket(ticketStr string) (*Ticket, error)
    // Verify a ticket with signature, expiration, token (if set) and ip (against the provided ip and if TKTCheckIpEnabled option is true)
    // VerifyTicket(ticket *Ticket, clientIp string) error
}
```

## Options

This implementation use the same options as you can found on [mod_auth_pubtkt doc](https://neon1.net/mod_auth_pubtkt/install.html) but with new features like:
- Ticket encryption (options: `TKTCypherTicketsWithPasswd` and `TKTCypherTicketsMethod`)
- Enable and disable check for IP (options: `TKTCheckIpEnabled` and `TKTCheckXForwardedIp`)

Here options you can set as `pubtkt.AuthPubTktOptions`:

```go
type AuthPubTktOptions struct {
	// A DSA or RSA public key in PEM format
	// This public key will be used to verify ticket signatures
	TKTAuthPublicKey string
	// String indicating what digest algorithm to use when verifying ticket signatures
	// Valid values are SHA1, DSS1, SHA224, SHA256, SHA384, and SHA512
	// If not specified, the old defaults of SHA1 (for an RSA public key) or DSS1 (for a DSA public key) will be used.
	TKTAuthDigest string
	// URL that users without a valid ticket will be redirected to
	// The originally requested URL will be appended as a GET parameter (normally named "back", but can be changed with TKTAuthBackArgName)
	TKTAuthLoginURL string
	// URL that users whose ticket has expired will be redirected to
	// If not set, TKTAuthLoginURL is used
	TKTAuthTimeoutURL string
	// Same as TKTAuthTimeoutURL, but in case the request was a POST
	// If not set, TKTAuthTimeoutURL is used (and if that is not set either, TKTAuthLoginURL)
	TKTAuthPostTimeoutURL string
	// URL that users whose ticket doesn't contain any of the required tokens (as set with TKTAuthToken) will be redirected to
	TKTAuthUnauthURL string
	// URL that users whose ticket is within the grace period (as set with the graceperiod key in the ticket) before the actual expiry will be redirected to.
	// Only GET requests are redirected; POST requests are accepted normally. The script at this URL should check the ticket and issue a new one
	// If not set, TKTAuthLoginURL is used
	TKTAuthRefreshURL string
	// A space separated list of headers to use for finding the ticket (case insensitive).
	// If this header specified is Cookie then the format of the value expects to be a valid cookie (subject to the TKTAuthCookieName directive).
	// Any other header assumes the value is a simple URL-encoded value of the ticket.
	// The first header that has content is tried and any other tickets in other header(s) are ignored.
	// example, use Cookie first, fallback to X-My-Auth: TKTAuthHeader: []string{"Cookie", "X-My-Auth"}
	// Default: Cookie
	TKTAuthHeader []string
	// Name of the authentication cookie to use
	// Default: auth_pubtkt
	TKTAuthCookieName string
	// Name of the GET argument with the originally requested URL (when redirecting to the login page)
	// Default: back
	TKTAuthBackArgName string
	// only accept tickets in HTTPS requests
	// Default: false
	TKTAuthRequireSSL bool
	// token that must be present in a ticket for access to be granted
	// Multiple tokens may be specified; only one of them needs to be present in the ticket (i.e. any token can match, not all tokens need to match)
	TKTAuthToken []string
	// if on, a fake Authorization header will be added to each request (username from ticket, fixed string "password" as the password).
	// This can be used in reverse proxy situations, and to prevent PHP from stripping username information from the request (which would then not be available for logging purposes)
	// Default: false
	TKTAuthFakeBasicAuth bool
	// if on, the value from the ticket's "bauth" field will be added to the request as a Basic Authorization header.
	// This can be used in reverse proxy situations where one needs complete control over the username and password (see also TKTAuthFakeBasicAuth, which should not be used at the same time).
	// Default: false
	TKTAuthPassthruBasicAuth bool
	// if set, the bauth value will be decrypted using the given key before it is added to the Authorization header.
	// length must be exactly 16 characters (AES 128)
	TKTAuthPassthruBasicKey string
	// If set it will crypt/encrypt the cookie or the content of the header with this passphrase (not a key but a passphrase like in openssl)
	TKTCypherTicketsWithPasswd string
	// Method of encryption under aes, it can be either cbc or ecb
	TKTCypherTicketsMethod string
	// If true it will check if ip which created the token is the correct ip who use it
	// Default: false
	TKTCheckIpEnabled bool
	// If true and TKTCheckIpEnabled is true it will check ip from header X-Forwarded-For instead client remote ip
	// default: false
	TKTCheckXForwardedIp bool
}
```

**Note**: Disclaimer about `TKTCypherTicketsMethod` with the ecb method, orange forked [mod_auth_pubtkt](https://neon1.net/mod_auth_pubtkt/) 
to add ticket encryption and use ecb method, **you must always chose to use cbc method**