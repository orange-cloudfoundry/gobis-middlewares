package jwt

import (
	"crypto/subtle"
	"fmt"
	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	f3jwt "github.com/form3tech-oss/jwt-go"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	log "github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
)

type JwtConfig struct {
	Jwt *JwtOptions `mapstructure:"jwt" json:"jwt" yaml:"jwt"`
}
type JwtOptions struct {
	// enable jwt middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// Algorithm to use to validate the token
	// This is mandatory due to a security issue (see: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries)
	Alg string `mapstructure:"alg" json:"alg" yaml:"alg"`
	// Secret or private key to verify the jwt
	// This is required
	Secret string `mapstructure:"secret" json:"secret" yaml:"secret"`
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool `mapstructure:"enable_auth_on_options" json:"enable_auth_on_options" yaml:"enable_auth_on_options"`
	// If not empty, it will validate that the jwt contains this audience
	Audience string `mapstructure:"audience" json:"audience" yaml:"audience"`
	// If not empty, it will validate that the jwt contains this issuer
	Issuer string `mapstructure:"issuer" json:"issuer" yaml:"issuer"`
	// Add custom check to verify that the jwt contains those specified claims with specified value
	CustomVerify map[string]string `mapstructure:"custom_verify" json:"custom_verify" yaml:"custom_verify"`
	// Set to true to not verify issued at of token (Useful when you have different time between user and server)
	NotVerifyIssuedAt bool `mapstructure:"not_verify_expire" json:"not_verify_expire" yaml:"not_verify_expire"`
	// Passthrough if a previous middleware already set user context
	// This is helpful when you want add user with basic auth middleware
	TrustCurrentUser bool `mapstructure:"trust_current_user" json:"trust_current_user" yaml:"trust_current_user"`
}

type Jwt struct{}

func NewJwt() *Jwt {
	return &Jwt{}
}
func (Jwt) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(JwtConfig)
	options := config.Jwt
	if options == nil || !options.Enabled {
		return handler, nil
	}
	err := utils.RequiredVal(
		options.Alg, "algorithm",
		options.Secret, "secret",
	)
	if err != nil {
		return handler, err
	}
	signingMethod := jwt.GetSigningMethod(options.Alg)
	if signingMethod == nil {
		return handler, fmt.Errorf("algorithm '%s' doesn't exists.", options.Alg)
	}
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *f3jwt.Token) (interface{}, error) {
			return checkTokenfunc(token, options, signingMethod, options.NotVerifyIssuedAt)
		},
		SigningMethod: signingMethod,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err string) {
			msg := fmt.Sprintf(
				"%s from route %s : %s",
				http.StatusText(403),
				gobis.RouteName(req),
				err,
			)
			http.Error(w, msg, 403)
		},
		EnableAuthOnOptions: options.EnableAuthOnOptions,
		Debug:               log.GetLevel() == log.DebugLevel,
	})
	return NewJwtHandler(jwtMiddleware, handler, options.TrustCurrentUser), nil
}
func (Jwt) Schema() interface{} {
	return JwtConfig{}
}

type JwtHandler struct {
	jwtMiddleware    *jwtmiddleware.JWTMiddleware
	next             http.Handler
	trustCurrentUser bool
}

func NewJwtHandler(jwtMiddleware *jwtmiddleware.JWTMiddleware, next http.Handler, trustCurrentUser bool) http.Handler {
	return &JwtHandler{jwtMiddleware, next, trustCurrentUser}
}
func (h JwtHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h.trustCurrentUser && gobis.Username(req) != "" {
		h.next.ServeHTTP(w, req)
		return
	}

	err := h.jwtMiddleware.CheckJWT(w, req)
	if err != nil {
		return
	}
	jwtToken := req.Context().Value(h.jwtMiddleware.Options.UserProperty).(*f3jwt.Token)
	mapClaims := jwtToken.Claims.(f3jwt.MapClaims)
	usrRegex := regexp.MustCompile("(?i)^(user|username|user_name)$")
	scopeRegex := regexp.MustCompile("(?i)^scope.*")
	for k, v := range mapClaims {
		if usrRegex.MatchString(k) && gobis.Username(req) == "" {
			gobis.SetUsername(req, fmt.Sprint(v))
			continue
		}
		if !scopeRegex.MatchString(k) {
			continue
		}
		if scopeStr, ok := v.(string); ok {
			gobis.AddGroups(req, strings.Split(scopeStr, " ")...)
		}
		if scopeSlice, ok := v.([]interface{}); ok {
			for _, group := range scopeSlice {
				gobis.AddGroups(req, fmt.Sprint(group))
			}

		}
	}
	if email, ok := mapClaims["email"]; ok && gobis.Username(req) == "" {
		gobis.SetUsername(req, fmt.Sprint(email))
	}
	if login, ok := mapClaims["login"]; ok && gobis.Username(req) == "" {
		gobis.SetUsername(req, fmt.Sprint(login))
	}
	h.next.ServeHTTP(w, req)
}
func checkTokenfunc(token *f3jwt.Token, options *JwtOptions, signingMethod jwt.SigningMethod, notVerifyIssuedAt bool) (interface{}, error) {
	mapClaims := token.Claims.(f3jwt.MapClaims)
	if notVerifyIssuedAt {
		mapClaims["iat"] = ""
	}
	err := mapClaims.Valid()
	if err != nil {
		return nil, err
	}
	if !verifyAudience(mapClaims, options.Audience) {
		return nil, fmt.Errorf("Token doesn't contains the requested audience.")
	}
	if options.Issuer != "" && !mapClaims.VerifyIssuer(options.Issuer, true) {
		return nil, fmt.Errorf("Token doesn't contains the requested issuer.")
	}
	for k, v := range options.CustomVerify {
		if mapClaims[k] == nil ||
			subtle.ConstantTimeCompare([]byte(v), []byte(fmt.Sprint(mapClaims[k]))) == 0 {
			return nil, fmt.Errorf("Token doesn't contains the requested %s.", k)
		}
	}
	return getSecretEncoded(options.Secret, signingMethod)
}
func verifyAudience(m f3jwt.MapClaims, audience string) bool {
	if audience == "" {
		return true
	}
	_, ok := m["aud"].(string)
	if ok {
		return m.VerifyAudience(audience, true)
	}
	audSlice, ok := m["aud"].([]interface{})
	if !ok {
		return false
	}
	for _, aud := range audSlice {
		if fmt.Sprint(aud) == audience {
			return true
		}
	}
	return false
}
func getSecretEncoded(secret string, signingMethod jwt.SigningMethod) (interface{}, error) {
	bSecret := []byte(secret)
	if strings.HasPrefix(signingMethod.Alg(), "HS") {
		return bSecret, nil
	}
	if strings.HasPrefix(signingMethod.Alg(), "ES") {
		encSecret, err := jwt.ParseECPublicKeyFromPEM(bSecret)
		if err == nil {
			return encSecret, nil
		}
		return jwt.ParseECPrivateKeyFromPEM(bSecret)
	}
	// if no return token use RSA
	encSecret, err := jwt.ParseRSAPublicKeyFromPEM(bSecret)
	if err == nil {
		return encSecret, nil
	}
	return jwt.ParseRSAPrivateKeyFromPEM(bSecret)
}
