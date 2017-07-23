package trace

import (
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
	"github.com/vulcand/oxy/trace"
	"os"
)

type TraceConfig struct {
	Trace *TraceOptions `mapstructure:"trace" json:"trace" yaml:"trace"`
}
type TraceOptions struct {
	// enable request and response capture
	Enabled         bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// add request headers to capture
	RequestHeaders  []string `mapstructure:"request_headers" json:"request_headers" yaml:"request_headers"`
	// add response headers to capture
	ResponseHeaders []string `mapstructure:"response_headers" json:"response_headers" yaml:"response_headers"`
}
type Trace struct{}

func NewTrace() *Trace {
	return &Trace{}
}
func (Trace) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(TraceConfig)
	options := config.Trace
	if options == nil || !options.Enabled {
		return handler, nil
	}
	traceOptions := make([]trace.Option, 0)
	if len(options.RequestHeaders) == 0 {
		traceOptions = append(traceOptions, trace.RequestHeaders(options.RequestHeaders...))
	}
	if len(options.ResponseHeaders) == 0 {
		traceOptions = append(traceOptions, trace.ResponseHeaders(options.ResponseHeaders...))
	}
	traceHandler, err := trace.New(handler, os.Stdout, traceOptions...)
	if err != nil {
		return handler, err
	}
	return traceHandler, err
}
func (Trace) Schema() interface{} {
	return TraceConfig{}
}