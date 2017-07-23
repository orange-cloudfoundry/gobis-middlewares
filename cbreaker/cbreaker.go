package cbreaker

import (
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
	"github.com/vulcand/oxy/cbreaker"
	"time"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
)

type CircuitBreakerConfig struct {
	CircuitBreaker *CircuitBreakerOptions `mapstructure:"circuit_breaker" json:"circuit_breaker" yaml:"circuit_breaker"`
}
type CircuitBreakerOptions struct {
	// enable conn limit middleware
	Enabled          bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Limit number of simultaneous connection (default to 20)
	Expression       string `mapstructure:"expression" json:"expression" yaml:"expression"`
	// Identify request source to limit the source
	// possible value are 'client.ip', 'request.host' or 'request.header.X-My-Header-Name'
	// (default: client.ip)
	FallbackUrl      string `mapstructure:"fallback_url" json:"fallback_url" yaml:"fallback_url"`
	// FallbackDuration is how long the CircuitBreaker will remain in the Tripped in second
	// state before trying to recover.
	FallbackDuration int64 `mapstructure:"fallback_duration" json:"fallback_duration" yaml:"fallback_duration"`
	// RecoveryDuration is how long the CircuitBreaker will take to ramp up in second
	// requests during the Recovering state.
	RecoveryDuration int64 `mapstructure:"recovery_duration" json:"recovery_duration" yaml:"recovery_duration"`
	// CheckPeriod is how long the CircuitBreaker will wait between successive in second
	// checks of the breaker condition.
	CheckPeriod      int64 `mapstructure:"check_period" json:"check_period" yaml:"check_period"`
}
type CircuitBreaker struct{}

func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{}
}
func (CircuitBreaker) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(CircuitBreakerConfig)
	options := config.CircuitBreaker
	if options == nil || !options.Enabled {
		return handler, nil
	}
	err := utils.RequiredVal(
		options.Expression, "expression",
		options.FallbackUrl, "fallback url",
	)
	if err != nil {
		return handler, err
	}
	routerFactory := gobis.NewRouterFactory()
	proxyRoute.Url = options.FallbackUrl
	proxyRoute.Methods = []string{}
	proxyRoute.RemoveProxyHeaders = false
	proxyRoute.Name = proxyRoute.Name + " fallback"
	fallbackHandler, err := routerFactory.CreateForwardHandler(proxyRoute)
	if err != nil {
		return handler, err
	}
	cbreakerOptions := []cbreaker.CircuitBreakerOption{cbreaker.Fallback(fallbackHandler)}
	if options.FallbackDuration > 0 {
		cbreakerOptions = append(
			cbreakerOptions,
			cbreaker.FallbackDuration(time.Second * time.Duration(options.FallbackDuration)),
		)
	}
	if options.RecoveryDuration > 0 {
		cbreakerOptions = append(
			cbreakerOptions,
			cbreaker.RecoveryDuration(time.Second * time.Duration(options.RecoveryDuration)),
		)
	}
	if options.CheckPeriod > 0 {
		cbreakerOptions = append(
			cbreakerOptions,
			cbreaker.CheckPeriod(time.Second * time.Duration(options.CheckPeriod)),
		)
	}
	finalHandler, err := cbreaker.New(handler, options.Expression, cbreakerOptions...)
	if err != nil {
		return handler, err
	}

	return finalHandler, nil
}
func (CircuitBreaker) Schema() interface{} {
	return CircuitBreakerConfig{}
}