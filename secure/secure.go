package secure

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/unrolled/secure"
	"net/http"
)

type SecureConfig struct {
	Secure *SecureOptions `mapstructure:"secure" json:"secure" yaml:"secure"`
}
type SecureOptions struct {
	// enable Secure
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
	AllowedHosts []string `mapstructure:"allowed_hosts" json:"allowed_hosts" yaml:"allowed_hosts"`
	// HostsProxyHeaders is a set of header keys that may hold a proxied hostname value for the request.
	HostsProxyHeaders []string `mapstructure:"hosts_proxy_headers" json:"hosts_proxy_headers" yaml:"hosts_proxy_headers"`
	// If SSLRedirect is set to true, then only allow https requests. Default is false.
	SSLRedirect bool `mapstructure:"ssl_redirect" json:"ssl_redirect" yaml:"ssl_redirect"`
	// If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
	SSLTemporaryRedirect bool `mapstructure:"ssl_temporary_redirect" json:"ssl_temporary_redirect" yaml:"ssl_temporary_redirect"`
	// SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
	SSLHost string `mapstructure:"ssl_host" json:"ssl_host" yaml:"ssl_host"`
	// SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
	SSLProxyHeaders map[string]string `mapstructure:"ssl_proxy_headers" json:"ssl_proxy_headers" yaml:"ssl_proxy_headers"`
	// STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
	STSSeconds int64 `mapstructure:"sts_seconds" json:"sts_seconds" yaml:"sts_seconds"`
	// If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool `mapstructure:"sts_include_subdomains" json:"sts_include_subdomains" yaml:"sts_include_subdomains"`
	// If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
	STSPreload bool `mapstructure:"sts_preload" json:"sts_preload" yaml:"sts_preload"`
	// If ForceSTSHeader is set to true, the STS header will be added even when the connection is HTTP. Default is false.
	ForceSTSHeader bool `mapstructure:"force_sts_header" json:"force_sts_header" yaml:"force_sts_header"`
	// If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
	FrameDeny bool `mapstructure:"frame_deny" json:"frame_deny" yaml:"frame_deny"`
	// CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option. Default is "".
	CustomFrameOptionsValue string `mapstructure:"custom_frame_options_value" json:"custom_frame_options_value" yaml:"custom_frame_options_value"`
	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
	ContentTypeNosniff bool `mapstructure:"content_type_nosniff" json:"content_type_nosniff" yaml:"content_type_nosniff"`
	// If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
	BrowserXssFilter bool `mapstructure:"browser_xss_filter" json:"browser_xss_filter" yaml:"browser_xss_filter"`
	// CustomBrowserXssValue allows the X-XSS-Protection header value to be set with a custom value. This overrides the BrowserXssFilter option. Default is "".
	CustomBrowserXssValue string `mapstructure:"custom_browser_xss_value" json:"custom_browser_xss_value" yaml:"custom_browser_xss_value"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
	ContentSecurityPolicy string `mapstructure:"content_security_policy" json:"content_security_policy" yaml:"content_security_policy"`
	// PublicKey implements HPKP to prevent MITM attacks with forged certificates. Default is "".
	PublicKey string `mapstructure:"public_key" json:"public_key" yaml:"public_key"`
	// Referrer Policy allows sites to control when browsers will pass the Referer header to other sites. Default is "".
	ReferrerPolicy string `mapstructure:"referrer_policy" json:"referrer_policy" yaml:"referrer_policy"`
	// When developing, the AllowedHosts, SSL, and STS options can cause some unwanted effects. Usually testing happens on http, not https, and on localhost, not your production domain... so set this to true for dev environment.
	// If you would like your development environment to mimic production with complete Host blocking, SSL redirects, and STS headers, leave this as false. Default if false.
	IsDevelopment bool `mapstructure:"is_development" json:"is_development" yaml:"is_development"`
}

func (o SecureOptions) ToSecureOptions() secure.Options {
	return secure.Options{
		AllowedHosts:            o.AllowedHosts,
		HostsProxyHeaders:       o.HostsProxyHeaders,
		SSLRedirect:             o.SSLRedirect,
		SSLTemporaryRedirect:    o.SSLTemporaryRedirect,
		SSLHost:                 o.SSLHost,
		SSLProxyHeaders:         o.SSLProxyHeaders,
		STSSeconds:              o.STSSeconds,
		STSIncludeSubdomains:    o.STSIncludeSubdomains,
		STSPreload:              o.STSPreload,
		ForceSTSHeader:          o.ForceSTSHeader,
		FrameDeny:               o.FrameDeny,
		CustomFrameOptionsValue: o.CustomFrameOptionsValue,
		ContentTypeNosniff:      o.ContentTypeNosniff,
		BrowserXssFilter:        o.BrowserXssFilter,
		CustomBrowserXssValue:   o.CustomBrowserXssValue,
		ContentSecurityPolicy:   o.ContentSecurityPolicy,
		PublicKey:               o.PublicKey,
		ReferrerPolicy:          o.ReferrerPolicy,
		IsDevelopment:           o.IsDevelopment,
	}
}

type Secure struct{}

func NewSecure() *Secure {
	return &Secure{}
}
func (Secure) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(SecureConfig)
	options := config.Secure
	if options == nil || !options.Enabled {
		return next, nil
	}
	secureMiddleware := secure.New(options.ToSecureOptions())
	return secureMiddleware.Handler(next), nil
}
func (Secure) Schema() interface{} {
	return SecureConfig{}
}
