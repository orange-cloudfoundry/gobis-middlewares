package authpubtkt

import (
	"encoding/base64"
	"github.com/orange-cloudfoundry/go-auth-pubtkt"
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
)

const XRemoteUserData = "X-Remote-User-Data"

type AuthPubTktConfig struct {
	AuthPubTkt *AuthPubTktOptions `mapstructure:"auth_pubtkt" json:"auth_pubtkt" yaml:"auth_pubtkt"`
}
type AuthPubTktOptions struct {
	// Enabled enable auth pubtkt
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// PublicKey A DSA or RSA public key in PEM format
	// This public key will be used to verify ticket signatures
	PublicKey string `mapstructure:"public_key" json:"public_key" yaml:"public_key"`
	// Digest String indicating what digest algorithm to use when verifying ticket signatures
	// Valid values are SHA1, DSS1, SHA224, SHA256, SHA384, and SHA512
	// If not specified, the old defaults of SHA1 (for an RSA public key) or DSS1 (for a DSA public key) will be used.
	Digest string `mapstructure:"digest" json:"digest" yaml:"digest"`
	// LoginURL URL that users without a valid ticket will be redirected to
	// The originally requested URL will be appended as a GET parameter (normally named "back", but can be changed with BackArgName)
	LoginURL string `mapstructure:"login_url" json:"login_url" yaml:"login_url"`
	// TimeoutURL URL that users whose ticket has expired will be redirected to
	// If not set, LoginURL is used
	TimeoutURL string `mapstructure:"timeout_url" json:"timeout_url" yaml:"timeout_url"`
	// PostTimeoutURL Same as TimeoutURL, but in case the request was a POST
	// If not set, TimeoutURL is used (and if that is not set either, LoginURL)
	PostTimeoutURL string `mapstructure:"post_timeout_url" json:"post_timeout_url" yaml:"post_timeout_url"`
	// UnauthURL URL that users whose ticket doesn't contain any of the required tokens (as set with Token) will be redirected to
	UnauthURL string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	// RefreshURL URL that users whose ticket is within the grace period (as set with the graceperiod key in the ticket) before the actual expiry will be redirected to.
	// Only GET requests are redirected; POST requests are accepted normally. The script at this URL should check the ticket and issue a new one
	// If not set, LoginURL is used
	RefreshURL string `mapstructure:"refresh_url" json:"refresh_url" yaml:"refresh_url"`
	// Headers A space separated list of headers to use for finding the ticket (case-insensitive).
	// If this header specified is Cookie then the format of the value expects to be a valid cookie (subject to the CookieName directive).
	// Any other header assumes the value is a simple URL-encoded value of the ticket.
	// The first header that has content is tried and any other tickets in other header(s) are ignored.
	// example, use Cookie first, fallback to X-My-Auth: Header: []string{"Cookie", "X-My-Auth"}
	// Default: Cookie
	Headers []string `mapstructure:"headers" json:"headers" yaml:"headers"`
	// CookieName Name of the authentication cookie to use
	// Default: auth_pubtkt
	CookieName string `mapstructure:"cookie_name" json:"cookie_name" yaml:"cookie_name"`
	// BackArgName Name of the GET argument with the originally requested URL (when redirecting to the login page)
	// Default: back
	BackArgName string `mapstructure:"back_arg_name" json:"back_arg_name" yaml:"back_arg_name"`
	// RequireSSL only accept tickets in HTTPS requests
	// Default: false
	RequireSSL bool `mapstructure:"require_ssl" json:"require_ssl" yaml:"require_ssl"`
	// Tokens token that must be present in a ticket for access to be granted
	// Multiple tokens may be specified; only one of them needs to be present in the ticket (i.e. any token can match, not all tokens need to match)
	Tokens []string `mapstructure:"tokens" json:"tokens" yaml:"tokens"`
	// FakeBasicAuth if on, a fake Authorization header will be added to each request (username from ticket, fixed string "password" as the password).
	// This can be used in reverse proxy situations, and to prevent PHP from stripping username information from the request (which would then not be available for logging purposes)
	// Default: false
	FakeBasicAuth bool `mapstructure:"fake_basic_auth" json:"fake_basic_auth" yaml:"fake_basic_auth"`
	// PassthruBasicAuth if on, the value from the ticket's "bauth" field will be added to the request as a Basic Authorization header.
	// This can be used in reverse proxy situations where one needs complete control over the username and password (see also FakeBasicAuth, which should not be used at the same time).
	// Default: false
	PassthruBasicAuth bool `mapstructure:"passthru_basic_auth" json:"passthru_basic_auth" yaml:"passthru_basic_auth"`
	// PassthruBasicKey if set, the bauth value will be decrypted using the given key before it is added to the Authorization header.
	// length must be exactly 16 characters (AES 128)
	PassthruBasicKey string `mapstructure:"passthru_basic_key" json:"passthru_basic_key" yaml:"passthru_basic_key"`
	// CypherPass If set it will crypt/encrypt the cookie with this passphrase (not a key but a passphrase like in openssl)
	CypherPass string `mapstructure:"cypher_pass" json:"cypher_pass" yaml:"cypher_pass"`
	// CypherMethod Method of encryption under aes, it can be either cbc or ecb
	CypherMethod string `mapstructure:"cypher_method" json:"cypher_method" yaml:"cypher_method"`
	// CheckIpEnabled If true it will check if ip which created the token is the correct ip who use it
	// Default: false
	CheckIpEnabled bool `mapstructure:"check_ip_enabled" json:"check_ip_enabled" yaml:"check_ip_enabled"`
	// CheckXForwardedIp If true and TKTCheckIpEnabled is true, it will check the IP from the X-Forwarded-For header instead of the client remote IP
	// default: false
	CheckXForwardedIp bool `mapstructure:"check_xforwarded_ip" json:"check_xforwarded_ip" yaml:"check_xforwarded_ip"`
	// TrustCurrentUser Passthrough if a previous middleware already set user context
	// This is helpful when you want to add a user with basic auth middleware
	TrustCurrentUser bool `mapstructure:"trust_current_user" json:"trust_current_user" yaml:"trust_current_user"`
}

type AuthPubTkt struct{}

func NewAuthPubTkt() *AuthPubTkt {
	return &AuthPubTkt{}
}
func (AuthPubTkt) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(AuthPubTktConfig)
	options := config.AuthPubTkt
	if options == nil || !options.Enabled {
		return next, nil
	}
	hijackHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if options.TrustCurrentUser && gobis.Username(req) != "" {
			next.ServeHTTP(w, req)
			return
		}
		ticket := pubtkt.TicketRequest(req)
		if ticket == nil {
			return
		}
		gobis.DirtHeader(req, "Authorization")
		req.Header.Set("Authorization", base64.StdEncoding.EncodeToString([]byte(ticket.String())))
		gobis.SetUsername(req, ticket.Uid)
		gobis.AddGroups(req, ticket.Tokens...)
		req.Header.Add(XRemoteUserData, ticket.Udata)
		next.ServeHTTP(w, req)
	})
	return pubtkt.NewAuthPubTktHandler(pubtkt.AuthPubTktOptions{
		TKTAuthPublicKey:           options.PublicKey,
		TKTAuthDigest:              options.Digest,
		TKTAuthLoginURL:            options.LoginURL,
		TKTAuthTimeoutURL:          options.TimeoutURL,
		TKTAuthPostTimeoutURL:      options.PostTimeoutURL,
		TKTAuthUnauthURL:           options.UnauthURL,
		TKTAuthRefreshURL:          options.RefreshURL,
		TKTAuthHeader:              options.Headers,
		TKTAuthCookieName:          options.CookieName,
		TKTAuthBackArgName:         options.BackArgName,
		TKTAuthRequireSSL:          options.RequireSSL,
		TKTAuthToken:               options.Tokens,
		TKTAuthFakeBasicAuth:       options.FakeBasicAuth,
		TKTAuthPassthruBasicAuth:   options.PassthruBasicAuth,
		TKTAuthPassthruBasicKey:    options.PassthruBasicKey,
		TKTCypherTicketsWithPasswd: options.CypherPass,
		TKTCypherTicketsMethod:     options.CypherMethod,
		TKTCheckIpEnabled:          options.CheckIpEnabled,
		TKTCheckXForwardedIp:       options.CheckXForwardedIp,
	}, hijackHandler, pubtkt.PanicOnError())
}
func (AuthPubTkt) Schema() interface{} {
	return AuthPubTktConfig{}
}
