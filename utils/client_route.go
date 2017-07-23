package utils

import (
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
	"crypto/tls"
)

type ClientRouteOption struct {
	// Set to true to use the same proxy as you could use for you route
	UseRouteTransport  bool `mapstructure:"use_route_transport" json:"use_route_transport" yaml:"use_route_transport"`
	// Set to true to skip certificate check (NOT RECOMMENDED)
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

func CreateClient(options ClientRouteOption, proxyRoute gobis.ProxyRoute) *http.Client {
	transport := gobis.NewDefaultTransport()
	transport.Proxy = http.ProxyFromEnvironment
	if options.UseRouteTransport {
		transport = gobis.NewRouteTransport(proxyRoute).(*http.Transport)
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: options.InsecureSkipVerify}
	return &http.Client{
		Transport: transport,
	}
}
