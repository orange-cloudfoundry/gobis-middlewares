package infopage

import (
	"encoding/json"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"net/http"
	"strings"
)

const (
	GobisHeaderPrefix = "x-gobis-"
)

type InfoPageConfig struct {
	InfoPage *InfoPageOptions `mapstructure:"info_page" json:"info_page" yaml:"info_page"`
}
type InfoPageOptions struct {
	// enable info page middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Path where the info page will be available (Default: "/gobis_info")
	// Be careful it will override any existing path with this name on upstream
	Path string `mapstructure:"path" json:"path" yaml:"path"`
	// Show in the info page the authorization header set in request
	// This permit to see, for example, token created by oauth2 middleware
	// (every handler use for login should write in Authorization token/string used to connect)
	ShowAuthorizationHeader bool `mapstructure:"show_authorization_header" json:"show_authorization_header" yaml:"show_authorization_header"`
	// Name of the key for authorization header to use in info page (Default: authorization)
	// ShowAuthorizationHeader must be true to set this value
	AuthorizationKeyName string `mapstructure:"authorization_key_name" json:"authorization_key_name" yaml:"authorization_key_name"`
}

type InfoPage struct{}

func NewInfoPage() *InfoPage {
	return &InfoPage{}
}
func (InfoPage) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(InfoPageConfig)
	options := config.InfoPage
	if options == nil || !options.Enabled {
		return next, nil
	}
	options.Path = utils.CondVal(options.Path, "/gobis_info").(string)
	options.AuthorizationKeyName = utils.CondVal(options.AuthorizationKeyName, "authorization").(string)
	return utils.PathHandler(options.Path, next, func(w http.ResponseWriter, req *http.Request) {
		infoMap := make(map[string]interface{})
		for name, values := range req.Header {
			name = strings.ToLower(name)
			if !strings.HasPrefix(name, GobisHeaderPrefix) ||
				len(values) == 0 ||
				gobis.IsDirtyHeader(req, name) {
				continue
			}
			name = strings.TrimPrefix(name, GobisHeaderPrefix)
			if len(values) > 1 {
				infoMap[name] = values
				continue
			}
			infoMap[name] = values[0]
		}
		username := gobis.Username(req)
		if username != "" {
			infoMap["username"] = username
		}
		groups := gobis.Groups(req)
		if len(groups) > 0 {
			infoMap["groups"] = groups
		}
		if options.ShowAuthorizationHeader {
			infoMap[options.AuthorizationKeyName] = req.Header.Get("Authorization")
		}
		b, _ := json.MarshalIndent(infoMap, "", "\t")
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}), nil
}
func (InfoPage) Schema() interface{} {
	return InfoPageConfig{}
}
