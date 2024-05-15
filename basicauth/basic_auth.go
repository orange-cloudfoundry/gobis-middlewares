package basicauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/goji/httpauth"
	"github.com/orange-cloudfoundry/gobis"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blowfish"
	"net/http"
)

type BasicAuthOptions []BasicAuthOption
type BasicAuthConfig struct {
	BasicAuth            BasicAuthOptions `mapstructure:"basic_auth" json:"basic_auth" yaml:"basic_auth"`
	BasicAuthPassthrough bool             `mapstructure:"basic_auth_passthrough" json:"basic_auth_passthrough" yaml:"basic_auth_passthrough"`
}
type BasicAuthOption struct {
	User     string   `mapstructure:"user" json:"user" yaml:"user"`
	Password string   `mapstructure:"password" json:"password" yaml:"password"`
	Groups   []string `mapstructure:"groups" json:"groups" yaml:"groups"`
	Crypted  bool     `mapstructure:"crypted" json:"crypted" yaml:"crypted"`
}

func (b BasicAuthOptions) Auth(user, password string, passthrough bool, req *http.Request) bool {
	gobis.DirtHeader(req, "Authorization")
	foundUser := b.findByUser(user)
	if foundUser.User == "" && passthrough {
		return true
	}
	if foundUser.User == "" {
		return false
	}
	gobis.SetUsername(req, user)
	gobis.AddGroups(req, foundUser.Groups...)
	// Compare the supplied credentials to those set in our options
	if foundUser.Crypted {
		err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password))
		if err == nil {
			return true
		}
		var keySizeError blowfish.KeySizeError
		if errors.As(err, &keySizeError) {
			panic(fmt.Sprintf(
				"orange-cloudfoundry/gobis/middlewares: Basic auth middleware, invalid crypted password for user '%s': %s",
				foundUser.User,
				err.Error(),
			))
		}
		return false
	}
	// Equalize lengths of supplied and required credentials
	// by hashing them
	givenUser := sha256.Sum256([]byte(user))
	givenPass := sha256.Sum256([]byte(password))
	requiredUser := sha256.Sum256([]byte(foundUser.User))
	requiredPass := sha256.Sum256([]byte(foundUser.Password))
	return subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) == 1 &&
		subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) == 1
}
func (b BasicAuthOptions) findByUser(user string) BasicAuthOption {
	for _, basicAuthConfig := range b {
		if basicAuthConfig.User == user {
			return basicAuthConfig
		}
	}
	return BasicAuthOption{}
}

type BasicAuth struct{}

func NewBasicAuth() *BasicAuth {
	return &BasicAuth{}
}
func (BasicAuth) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(BasicAuthConfig)
	if len(config.BasicAuth) == 0 {
		return handler, nil
	}
	return httpauth.BasicAuth(httpauth.AuthOptions{
		AuthFunc: func(user, password string, req *http.Request) bool {
			return config.BasicAuth.Auth(user, password, config.BasicAuthPassthrough, req)
		},
	})(handler), nil
}
func (BasicAuth) Schema() interface{} {
	return BasicAuthConfig{}
}
