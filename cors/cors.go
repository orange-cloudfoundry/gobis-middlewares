package cors

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/rs/cors"
	"net/http"
)

type CorsConfig struct {
	Cors *CorsOptions `mapstructure:"cors" json:"cors" yaml:"cors"`
}

type CorsOptions struct {
	// Enabled enable conn limit middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters
	// (i.e.: http://*.domain.com). Usage of wildcards implies a small performance penalty.
	// Only one wildcard can be used per origin.
	// Default value is `["*"]`
	AllowedOrigins []string `mapstructure:"allowed_origins" json:"allowed_origins" yaml:"allowed_origins"`
	// AllowedMethods is a list of methods the client is allowed to use with
	// cross-domain requests. Default value is simple methods (GET and POST)
	AllowedMethods []string `mapstructure:"allowed_methods" json:"allowed_methods" yaml:"allowed_methods"`
	// AllowedHeaders is list of non-simple headers the client is allowed to use with
	// cross-domain requests.
	// If the special "*" value is present in the list, all headers will be allowed.
	// Default value is [] but "Origin" is always appended to the list.
	AllowedHeaders []string `mapstructure:"allowed_headers" json:"allowed_headers" yaml:"allowed_headers"`
	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	ExposedHeaders []string `mapstructure:"exposed_headers" json:"exposed_headers" yaml:"exposed_headers"`
	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool `mapstructure:"allow_credentials" json:"allow_credentials" yaml:"allow_credentials"`
	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached
	MaxAge int `mapstructure:"max_age" json:"max_age" yaml:"max_age"`
	// OptionsPassthrough instructs preflight to let other potential next handlers to
	// process the OPTIONS method. Turn this on if your application handles OPTIONS.
	OptionsPassthrough bool `mapstructure:"options_passthrough" json:"options_passthrough" yaml:"options_passthrough"`
}

type Cors struct{}

func NewCors() *Cors {
	return &Cors{}
}
func (Cors) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	corsStruct := params.(CorsConfig)
	corsOptions := corsStruct.Cors
	if corsOptions == nil || !corsOptions.Enabled {
		return handler, nil
	}
	if len(corsOptions.AllowedMethods) == 0 {
		corsOptions.AllowedMethods = []string{"GET", "POST"}
	}
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:     corsOptions.AllowedOrigins,
		AllowedMethods:     corsOptions.AllowedMethods,
		AllowedHeaders:     corsOptions.AllowedHeaders,
		ExposedHeaders:     corsOptions.ExposedHeaders,
		AllowCredentials:   corsOptions.AllowCredentials,
		MaxAge:             corsOptions.MaxAge,
		OptionsPassthrough: corsOptions.OptionsPassthrough,
	})
	return corsHandler.Handler(handler), nil
}
func (Cors) Schema() interface{} {
	return CorsConfig{}
}
