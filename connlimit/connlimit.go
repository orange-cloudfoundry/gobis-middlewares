package connlimit

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"github.com/vulcand/oxy/connlimit"
	"net/http"
)

type ConnLimitConfig struct {
	ConnLimit *ConnLimitOptions `mapstructure:"conn_limit" json:"conn_limit" yaml:"conn_limit"`
}
type ConnLimitOptions struct {
	// Enabled enable conn limit middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Limit number of simultaneous connection (default to 20)
	Limit int64 `mapstructure:"limit" json:"limit" yaml:"limit"`
	// SourceIdentifier Identify request source to limit the source
	// possible value are 'client.ip', 'request.host' or 'request.header.X-My-Header-Name'
	// (default: client.ip)
	// if empty and a username exists in context, the source will be set to this content (this allows to limit connections by the username from the auth middleware)
	// for context see: https://godoc.org/github.com/orange-cloudfoundry/gobis/proxy/ctx#Username
	SourceIdentifier string `mapstructure:"source_identifier" json:"source_identifier" yaml:"source_identifier"`
}

type ConnLimit struct{}

func NewConnLimit() *ConnLimit {
	return &ConnLimit{}
}
func (ConnLimit) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(ConnLimitConfig)
	options := config.ConnLimit
	if options == nil || !options.Enabled {
		return handler, nil
	}
	if options.Limit == 0 {
		options.Limit = int64(20)
	}
	extractor, err := utils.NewGobisSourceExtractor(options.SourceIdentifier)
	if err != nil {
		return handler, err
	}
	finalHandler, err := connlimit.New(handler, extractor, options.Limit)
	if err != nil {
		return handler, err
	}
	return finalHandler, nil
}
func (ConnLimit) Schema() interface{} {
	return ConnLimitConfig{}
}
