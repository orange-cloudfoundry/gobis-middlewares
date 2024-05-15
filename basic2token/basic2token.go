package basic2token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/goji/httpauth"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Basic2TokenConfig struct {
	Basic2Token *Basic2TokenOptions `mapstructure:"basic2token" json:"basic2token" yaml:"basic2token"`
}
type Basic2TokenOptions struct {
	utils.ClientRouteOption `mapstructure:",squash"`
	// AccessTokenUri Uri to retrieve access token e.g.: https://my.uaa.local/oauth/token
	AccessTokenUri string `mapstructure:"access_token_uri" json:"access_token_uri" yaml:"access_token_uri"`
	// ClientId Client id which will connect user on behalf him
	ClientId string `mapstructure:"client_id" json:"client_id" yaml:"client_id"`
	// ClientSecret Client secret which will connect user on behalf him
	ClientSecret string `mapstructure:"client_secret" json:"client_secret" yaml:"client_secret"`
	// TokenFormat Some OAuth servers can be configured to use a different token format;
	// if you want an opaque token from UAA you will set this value to "opaque"
	TokenFormat string `mapstructure:"token_format" json:"token_format" yaml:"token_format"`
	// TokenType Permit to basic2token to detect if a oauth token has been already set
	// If token was already given it will forward to the next handler without trying to acquire a new token
	// Default: bearer
	TokenType string `mapstructure:"token_type" json:"token_type" yaml:"token_type"`
	// ParamsAsJson By default request token is sent by post form, set to true to send as JSON
	ParamsAsJson bool `mapstructure:"params_as_json" json:"params_as_json" yaml:"params_as_json"`
	// TrustCurrentUser Passthrough if a previous middleware already set user context
	// This is helpful when you want to add a user with basic auth middleware
	TrustCurrentUser bool `mapstructure:"trust_current_user" json:"trust_current_user" yaml:"trust_current_user"`
}
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Jti          string `json:"jti"`
}
type Basic2TokenAuth struct {
	client  *http.Client
	options Basic2TokenOptions
}

func NewBasic2TokenAuth(client *http.Client, options Basic2TokenOptions) *Basic2TokenAuth {
	return &Basic2TokenAuth{
		client:  client,
		options: options,
	}
}

func (a Basic2TokenAuth) Auth(user, password string, origRequest *http.Request) bool {
	var body io.Reader
	var contentType string
	if a.options.ParamsAsJson {
		body, contentType = a.generateJsonBody(user, password)
	} else {
		body, contentType = a.generateFormBody(user, password)
	}
	req, _ := http.NewRequest("POST", a.options.AccessTokenUri, body)
	req.SetBasicAuth(a.options.ClientId, a.options.ClientSecret)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", contentType)
	resp, err := a.client.Do(req)
	if err != nil {
		panic(fmt.Sprintf("Error when getting token for %s: %s", user, err.Error()))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return false
		}
		b, _ := io.ReadAll(resp.Body)
		panic(fmt.Sprintf("Error from oauth server %d: %s", resp.StatusCode, string(b)))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Error when getting token for %s: %s", user, err.Error()))
	}
	var accessResp AccessTokenResponse
	err = json.Unmarshal(b, &accessResp)
	if err != nil {
		panic(fmt.Sprintf("Error when getting token for %s: %s", user, err.Error()))
	}
	tokenType := accessResp.TokenType
	if tokenType == "" {
		tokenType = "bearer"
	}
	gobis.UndirtHeader(origRequest, "Authorization")

	origRequest.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessResp.AccessToken))
	if accessResp.Scope != "" {
		groups := strings.Split(accessResp.Scope, " ")
		gobis.AddGroups(origRequest, groups...)
	}
	gobis.SetUsername(origRequest, user)
	return true
}
func (a Basic2TokenAuth) generateFormBody(user, password string) (io.Reader, string) {
	formValues := make(url.Values)
	formValues.Add("grant_type", "password")
	formValues.Add("username", user)
	formValues.Add("password", password)
	if a.options.TokenFormat != "" {
		formValues.Add("token_format", a.options.TokenFormat)
	}
	return strings.NewReader(formValues.Encode()), "application/x-www-form-urlencoded"
}
func (a Basic2TokenAuth) generateJsonBody(user, password string) (io.Reader, string) {
	params := struct {
		GrantType   string `json:"grant_type"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		TokenFormat string `json:"token_format,omitempty"`
	}{"password", user, password, a.options.TokenFormat}
	b, _ := json.Marshal(params)
	return bytes.NewReader(b), "application/json"
}

type Basic2Token struct{}

func NewBasic2Token() *Basic2Token {
	return &Basic2Token{}
}
func (h Basic2Token) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(Basic2TokenConfig)
	options := config.Basic2Token
	if options == nil {
		return handler, nil
	}
	err := utils.RequiredVal(
		options.AccessTokenUri, "access token uri",
		options.ClientId, "client id",
	)
	if err != nil {
		return handler, err
	}
	_, err = url.Parse(options.AccessTokenUri)
	if err != nil {
		return handler, err
	}
	options.TokenType = utils.CondVal(options.TokenType, "bearer").(string)
	client := utils.CreateClient(options.ClientRouteOption, proxyRoute)
	basic2TokenAuth := NewBasic2TokenAuth(client, *options)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if options.TrustCurrentUser && gobis.Username(req) != "" {
			handler.ServeHTTP(w, req)
			return
		}
		// if token already passed, the handler go to next handler without try to do oauth
		authHeader := strings.ToLower(req.Header.Get("Authorization"))
		if strings.HasPrefix(authHeader, strings.ToLower(options.TokenType)) {
			handler.ServeHTTP(w, req)
			return
		}
		httpauth.BasicAuth(httpauth.AuthOptions{
			AuthFunc: basic2TokenAuth.Auth,
		})(handler).ServeHTTP(w, req)
	}), nil
}
func (h Basic2Token) Schema() interface{} {
	return Basic2TokenConfig{}
}
