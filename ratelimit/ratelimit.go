package ratelimit

import (
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
	"github.com/vulcand/oxy/ratelimit"
	"time"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
)

type RateLimitConfig struct {
	RateLimit *RateLimitOptions `mapstructure:"rate_limit" json:"rate_limit" yaml:"rate_limit"`
}
type RateLimitOptions struct {
	// enable rate limit
	Enabled          bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Limit number of requests (default to 5000)
	Limit            int64 `mapstructure:"limit" json:"limit" yaml:"limit"`
	// Number of seconds when the limit will be reset (default to 1800)
	ResetTime        int64 `mapstructure:"reset_time" json:"reset_time" yaml:"reset_time"`
	// Identify request source to limit the source
	// possible value are 'client.ip', 'request.host' or 'request.header.X-My-Header-Name'
	// if empty and a username exists in context the source will be set to this content (this allow to rate limit by username from auth middleware)
	// for context see: https://godoc.org/github.com/orange-cloudfoundry/gobis/proxy/ctx#Username
	SourceIdentifier string `mapstructure:"source_identifier" json:"source_identifier" yaml:"source_identifier"`
}
type RateLimit struct{}

func NewRateLimit() *RateLimit {
	return &RateLimit{}
}
func (RateLimit) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(RateLimitConfig)
	options := config.RateLimit
	if options == nil || !options.Enabled {
		return handler, nil
	}
	if options.ResetTime == 0 {
		options.ResetTime = int64(1800)
	}
	if options.Limit == 0 {
		options.Limit = int64(5000)
	}
	extractor, err := utils.NewGobisSourceExtractor(options.SourceIdentifier)
	if err != nil {
		return handler, err
	}
	rateSet := ratelimit.NewRateSet()
	rateSet.Add(time.Second * time.Duration(options.ResetTime), 1, options.Limit)
	limitHandler, err := ratelimit.New(handler, extractor, rateSet)
	if err != nil {
		return handler, err
	}
	return limitHandler, nil
}
func (RateLimit) Schema() interface{} {
	return RateLimitConfig{}
}