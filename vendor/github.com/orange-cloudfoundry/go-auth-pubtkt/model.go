package pubtkt

import (
	"fmt"
	"strings"
	"time"
)

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
	// If set it will crypt/encrypt the cookie with this passphrase (not a key but a passphrase like in openssl)
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
type Ticket struct {
	Uid         string    `mapstructure:"uid"`
	Cip         string    `mapstructure:"cip"`
	Bauth       string    `mapstructure:"bauth"`
	Validuntil  time.Time `mapstructure:"validuntil"`
	Graceperiod time.Time `mapstructure:"graceperiod"`
	Tokens      []string  `mapstructure:"tokens"`
	Udata       string    `mapstructure:"udata"`
	Sig         string    `mapstructure:"sig"`
}

func (t Ticket) DataString() string {
	data := make([]string, 0)
	if t.Uid != "" {
		data = append(data, fmt.Sprintf("%s=%s", "uid", t.Uid))
	}
	if t.Cip != "" {
		data = append(data, fmt.Sprintf("%s=%s", "cip", t.Cip))
	}
	if t.Bauth != "" {
		data = append(data, fmt.Sprintf("%s=%s", "bauth", t.Bauth))
	}
	if !t.Validuntil.IsZero() {
		data = append(data, fmt.Sprintf("%s=%d", "validuntil", t.Validuntil.Unix()))
	}
	if !t.Graceperiod.IsZero() {
		data = append(data, fmt.Sprintf("%s=%d", "graceperiod", t.Graceperiod.Unix()))
	}
	if len(t.Tokens) != 0 {
		data = append(data, fmt.Sprintf("%s=%s", "tokens", strings.Join(t.Tokens, ",")))
	}
	if t.Udata != "" {
		data = append(data, fmt.Sprintf("%s=%s", "udata", t.Udata))
	}
	return strings.Join(data, ";")
}
func (t Ticket) String() string {
	data := t.DataString()
	if t.Sig != "" {
		data += fmt.Sprintf(";%s=%s", "sig", t.Sig)
	}
	return data
}
