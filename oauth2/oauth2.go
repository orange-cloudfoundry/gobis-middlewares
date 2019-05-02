package oauth2

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"net/http"
	"net/url"
)

type Oauth2Config struct {
	Oauth2 *Oauth2Options `mapstructure:"oauth2" json:"oauth2" yaml:"oauth2"`
}

type Oauth2Options struct {
	utils.ClientRouteOption `mapstructure:",squash"`
	// enable oauth2 middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Uri to create authoriation code e.g.: https://my.uaa.local/oauth/authorize
	AuthorizationUri string `mapstructure:"authorization_uri" json:"authorization_uri" yaml:"authorization_uri"`
	// Uri to retrieve access token e.g.: https://my.uaa.local/oauth/token
	AccessTokenUri string `mapstructure:"access_token_uri" json:"access_token_uri" yaml:"access_token_uri"`
	// Uri to retrieve user information e.g.: https://my.uaa.local/userInfo
	// if set context username will be filled for other middlewares from this information
	UserInfoUri string `mapstructure:"user_info_uri" json:"user_info_uri" yaml:"user_info_uri"`
	// Client id set in your oauth provider
	// This field is mandatory
	ClientId string `mapstructure:"client_id" json:"client_id" yaml:"client_id"`
	// Client secret set in your oauth provider
	ClientSecret string `mapstructure:"client_secret" json:"client_secret" yaml:"client_secret"`
	// Permit to basic2token to detect if a oauth token has been already set
	// If token was already given it will forward to the next handler without trying to acquire a new token
	// Default: bearer
	TokenType string `mapstructure:"token_type" json:"token_type" yaml:"token_type"`
	// Set to true to pass the redirect url to oauth2 server (will be forged with login path)
	UseRedirectUrl bool `mapstructure:"use_redirect_url" json:"use_redirect_url" yaml:"use_redirect_url"`
	// Path where token will be retrieve (Default: "/login")
	// Be careful it will override any existing path with this name on upstream
	LoginPath string `mapstructure:"login_path" json:"login_path" yaml:"login_path"`
	// Path where the session will be deleted (Default: "/logout")
	// Be careful it will override any existing path with this name on upstream
	LogoutPath string `mapstructure:"logout_path" json:"logout_path" yaml:"logout_path"`
	// authorization key used by the session, it should be a strong key
	// this field is mandatory
	AuthKey string `mapstructure:"auth_key" json:"auth_key" yaml:"auth_key"`
	// You can set an encryption key for the session, the key must have one of this size: 16, 32 or 64
	EncKey string `mapstructure:"enc_key" json:"enc_key" yaml:"enc_key"`
	// AccessTypeOnline and AccessTypeOffline are options passed
	// to the Options.AuthCodeURL method. They modify the
	// "access_type" field that gets sent in the URL returned by
	// AuthCodeURL
	// Default: online
	AccessType string `mapstructure:"access_type" json:"access_type" yaml:"access_type"`
	// Scopes that your app need
	// context group will be filled for other middlewares with these scopes
	Scopes []string `mapstructure:"scopes" json:"scopes" yaml:"scopes"`
	// By default when login or logout user will be redirect to the previous url
	// If this params is set, user will be redirected to this url after login or logout
	RedirectLogUrl string `mapstructure:"redirect_log_url" json:"redirect_log_url" yaml:"redirect_log_url"`
	// Set to true to pass the oauth2 token to upstream through authorization header
	// This is false by default
	PassToken bool `mapstructure:"pass_token" json:"pass_token" yaml:"pass_token"`
	// Passthrough if a previous middleware already set user context
	// This is helpful when you want add user with basic auth middleware
	TrustCurrentUser bool `mapstructure:"trust_current_user" json:"trust_current_user" yaml:"trust_current_user"`
}

type Oauth2 struct{}

func NewOauth2() *Oauth2 {
	return &Oauth2{}
}

func (Oauth2) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(Oauth2Config)
	options := config.Oauth2
	if options == nil || !options.Enabled {
		return next, nil
	}
	err := utils.RequiredVal(
		options.AuthorizationUri, "authorization uri",
		options.AccessTokenUri, "access token uri",
		options.ClientId, "client id",
		options.AuthKey, "authorization key",
	)
	if err != nil {
		return next, err
	}
	options.TokenType = utils.CondVal(options.TokenType, "bearer").(string)
	options.LoginPath = utils.CondVal(options.LoginPath, "/login").(string)
	options.LogoutPath = utils.CondVal(options.LogoutPath, "/logout").(string)
	options.AccessType = utils.CondVal(options.AccessType, "online").(string)
	oauth2Handler := NewOauth2Handler(
		options,
		next,
		utils.CreateClient(options.ClientRouteOption, proxyRoute),
		func(req *http.Request) *url.URL {
			path := proxyRoute.CreateRoutePath(options.LoginPath)
			var redirectUrl *url.URL
			if proxyRoute.ForwardedHeader == "" {
				proto := "https"
				if req.TLS == nil {
					proto = "http"
				}
				redirectUrl, _ = url.Parse(proto + "://" + req.Host)
			} else {
				redirectUrl = proxyRoute.UpstreamUrl(req)
			}
			redirectUrl.Path = path
			redirectUrl.RawQuery = ""
			return redirectUrl
		},
	)
	return oauth2Handler, nil
}

func (Oauth2) Schema() interface{} {
	return Oauth2Config{}
}
