package middlewares

import (
	"net/http"
	"net/url"
	"io"
	"encoding/json"
	"bytes"
	"strings"
	"io/ioutil"
	"fmt"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/mitchellh/mapstructure"
	"github.com/goji/httpauth"
	"crypto/tls"
)

type Basic2TokenConfig struct {
	Basic2Token *Basic2TokenOptions `mapstructure:"basic2token" json:"basic2token" yaml:"basic2token"`
}
type Basic2TokenOptions struct {
	// Uri to retrieve access token e.g.: https://my.uaa.local/oauth/token
	AccessTokenUri     string `mapstructure:"access_token_uri" json:"access_token_uri" yaml:"access_token_uri"`
	// Client id which will connect user on behalf him
	ClientId           string `mapstructure:"client_id" json:"client_id" yaml:"client_id"`
	// Client secret which will connect user on behalf him
	ClientSecret       string `mapstructure:"client_secret" json:"client_secret" yaml:"client_secret"`
	// Some oauth server can be configured to use a different of token
	// if you want an opaque token from uaa you will set this value to "opaque"
	TokenFormat        string `mapstructure:"token_format" json:"token_format" yaml:"token_format"`
	// Permit to basic2token to detect if a oauth token has been already set
	// If token was already given it will forward to the next handler without trying to acquire a new token
	// Default: bearer
	TokenType          string `mapstructure:"token_type" json:"token_type" yaml:"token_type"`
	// By default request token is sent by post form, set to true to send as json
	ParamsAsJson       bool `mapstructure:"params_as_json" json:"params_as_json" yaml:"params_as_json"`
	// Set to true to use the same proxy as you could use for you route
	UseRouteTransport  bool `mapstructure:"use_route_transport" json:"use_route_transport" yaml:"use_route_transport"`
	// Set to true to skip certificate check (NOT RECOMMENDED)
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int `json:"expires_in"`
	Scope        string `json:"scope"`
	Jti          string `json:"jti"`
}
type Basic2TokenAuth struct {
	client  *http.Client
	options Basic2TokenOptions
}

func NewBasic2TokenAuth(client *http.Client, options Basic2TokenOptions) *Basic2TokenAuth {
	return &Basic2TokenAuth{
		client: client,
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
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return false
		}
		b, _ := ioutil.ReadAll(resp.Body)
		panic(fmt.Sprintf("Error from oauth server %d: %s", resp.StatusCode, string(b)))
		return false
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Error when getting token for %s: %s", user, err.Error()))
		return false
	}
	var accessResp AccessTokenResponse
	err = json.Unmarshal(b, &accessResp)
	if err != nil {
		panic(fmt.Sprintf("Error when getting token for %s: %s", user, err.Error()))
		return false
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

func Basic2Token(proxyRoute gobis.ProxyRoute, handler http.Handler) (http.Handler, error) {
	var config Basic2TokenConfig
	err := mapstructure.Decode(proxyRoute.ExtraParams, &config)
	if err != nil {
		return handler, err
	}
	options := config.Basic2Token
	if options == nil {
		return handler, nil
	}
	if options.AccessTokenUri == "" {
		return handler, fmt.Errorf("access token uri cannot be empty")
	}
	if options.ClientId == "" {
		return handler, fmt.Errorf("client id cannot be empty")
	}
	_, err = url.Parse(options.AccessTokenUri)
	if err != nil {
		return handler, err
	}
	if options.TokenType == "" {
		options.TokenType = "bearer"
	}
	transport := gobis.NewDefaultTransport()
	transport.Proxy = http.ProxyFromEnvironment
	if options.UseRouteTransport {
		transport = gobis.NewRouteTransport(proxyRoute).(*http.Transport)
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: options.InsecureSkipVerify}
	client := &http.Client{
		Transport: transport,
	}
	basic2TokenAuth := NewBasic2TokenAuth(client, *options)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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