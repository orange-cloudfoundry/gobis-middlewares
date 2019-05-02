package oauth2request

import (
	"context"
	"fmt"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"net/http"
)

type Oauth2RequestConfig struct {
	Oauth2Request *Oauth2RequestOptions `mapstructure:"oauth2request" json:"oauth2oauth2request" yaml:"oauth2oauth2request"`
}
type Oauth2RequestOptions struct {
	utils.ClientRouteOption `mapstructure:",squash"`
	// enable oauth2 middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Uri to retrieve access token e.g.: https://my.uaa.local/oauth/token
	AccessTokenUri string `mapstructure:"access_token_uri" json:"access_token_uri" yaml:"access_token_uri"`
	// Client id set in your oauth provider
	// This field is mandatory
	ClientId string `mapstructure:"client_id" json:"client_id" yaml:"client_id"`
	// Client secret set in your oauth provider
	ClientSecret string `mapstructure:"client_secret" json:"client_secret" yaml:"client_secret"`
	// Scopes that your app need
	// context group will be filled for other middlewares with these scopes
	Scopes []string `mapstructure:"scopes" json:"scopes" yaml:"scopes"`
}

type Oauth2Request struct{}

func NewOauth2Request() *Oauth2Request {
	return &Oauth2Request{}
}

func (Oauth2Request) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(Oauth2RequestConfig)
	options := config.Oauth2Request
	if options == nil || !options.Enabled {
		return next, nil
	}
	err := utils.RequiredVal(
		options.AccessTokenUri, "access token uri",
		options.ClientId, "client id",
	)
	if err != nil {
		return next, err
	}
	httpClient := utils.CreateClient(options.ClientRouteOption, proxyRoute)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	ccConfig := clientcredentials.Config{
		ClientID:     options.ClientId,
		ClientSecret: options.ClientSecret,
		Scopes:       options.Scopes,
		TokenURL:     options.AccessTokenUri,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, err := ccConfig.Token(ctx)
		if err != nil {
			panic(err)
		}
		req.Header.Set(
			"Authorization",
			fmt.Sprintf("%s %s", token.TokenType, token.AccessToken),
		)
	}), nil
}

func (Oauth2Request) Schema() interface{} {
	return Oauth2RequestConfig{}
}
