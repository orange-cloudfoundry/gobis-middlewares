package ceftrace

import (
	"context"
	"fmt"
	"github.com/ArthurHlt/logrus-cef-formatter"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strings"
)

type CefTraceConfig struct {
	CefTrace *CefTraceOptions `mapstructure:"cef_trace" json:"cef_trace" yaml:"cef_trace"`
}

type CefTraceOptions struct {
	// enable request and response capture
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// (Required) Device vendor
	DeviceVendor string `mapstructure:"device_vendor" json:"device_vendor" yaml:"device_vendor"`
	// (Required) Device product
	DeviceProduct string `mapstructure:"device_product" json:"device_product" yaml:"device_product"`
	// (Required) Device version
	DeviceVersion string `mapstructure:"device_version" json:"device_version" yaml:"device_version"`
	// (Optional) Key Signature ID
	KeySignatureID string `mapstructure:"key_signature_id" json:"key_signature_id" yaml:"key_signature_id"`
	// Set to true to write in stderr instead of stdout
	InStderr bool `mapstructure:"in_stderr" json:"in_stderr" yaml:"in_stderr"`
}
type CefTrace struct{}

func NewCefTrace() *CefTrace {
	return &CefTrace{}
}

func (CefTrace) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(CefTraceConfig)
	options := config.CefTrace
	if options == nil || !options.Enabled {
		return next, nil
	}
	err := utils.RequiredVal(
		options.DeviceVendor, "device vendor",
		options.DeviceProduct, "device product",
		options.DeviceVersion, "device version",
	)
	if err != nil {
		return next, err
	}
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	if options.InStderr {
		logger.SetOutput(os.Stderr)
	}
	logger.Formatter = cef.NewCEFFormatter(options.DeviceVendor, options.DeviceProduct, options.DeviceVersion)
	var entry *logrus.Entry
	entry = logger.WithContext(context.TODO())
	if options.KeySignatureID != "" {
		entry = logger.WithField(cef.KeySignatureID, options.KeySignatureID)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, req)
		entry.
			WithField("request", req.URL.Path).
			WithField("requestMethod", req.Method).
			WithField("httpStatusCode", sw.status).
			WithField("src", strings.Split(req.RemoteAddr, ":")[0]).
			WithField("suser", gobis.Username(req)).
			WithField("sgroups", strings.Join(gobis.Groups(req), ",")).
			WithField("xForwardedFor", strings.Replace(req.Header.Get("x-forwarded-for"), " ", "", -1)).
			Info(fmt.Sprintf("%s %s", req.Method, req.URL.Path))
	}), err
}

func (CefTrace) Schema() interface{} {
	return CefTraceConfig{}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	length int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.length += n
	return n, err
}
