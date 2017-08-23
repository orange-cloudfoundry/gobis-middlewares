package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const tokenSessKey = "token"
const stateSessKey = "state"
const refererSessKey = "referer"

type Oauth2Handler struct {
	options            *Oauth2Options
	store              *sessions.CookieStore
	oauth2Conf         *oauth2.Config
	next               http.Handler
	client             *http.Client
	callbackCreateFunc func(*http.Request) *url.URL
}

func NewOauth2Handler(options *Oauth2Options, next http.Handler, client *http.Client, callbackCreateFunc func(*http.Request) *url.URL) *Oauth2Handler {
	return &Oauth2Handler{
		options:            options,
		store:              createSessStore(options.AuthKey, options.EncKey),
		oauth2Conf:         createOauth2Conf(options),
		next:               next,
		client:             client,
		callbackCreateFunc: callbackCreateFunc,
	}
}

func (h Oauth2Handler) sessionHasToken(sess *sessions.Session) bool {
	return sess.Values[tokenSessKey] != nil
}
func (h Oauth2Handler) reqHasToken(req *http.Request) bool {
	authHeader := strings.ToLower(req.Header.Get("Authorization"))
	return strings.HasPrefix(authHeader, strings.ToLower(h.options.TokenType))
}
func (h Oauth2Handler) reqToken(req *http.Request) string {
	if !h.reqHasToken(req) {
		return ""
	}
	authHeader := strings.ToLower(req.Header.Get("Authorization"))
	return strings.Split(authHeader, " ")[1]
}
func (h Oauth2Handler) getSession(req *http.Request) (*sessions.Session, error) {
	return h.store.Get(req, "session-"+gobis.RouteName(req))
}
func (h Oauth2Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	gobis.DirtHeader(req, "Authorization")
	if h.options.UseRedirectUrl {
		h.oauth2Conf.RedirectURL = h.callbackCreateFunc(req).String()
	}
	if gobis.Path(req) == h.options.LoginPath {
		h.LoginHandler(w, req)
		return
	}
	if gobis.Path(req) == h.options.LogoutPath {
		h.LogoutHandler(w, req)
		return
	}
	sess, err := h.getSession(req)
	if err != nil {
		panic(err)
	}

	if h.reqHasToken(req) || h.sessionHasToken(sess) {
		h.serveNext(w, req, sess)
		return
	}

	stateCode := utils.RandString(5)

	sess.Values[stateSessKey] = stateCode
	authCodeOpt := make([]oauth2.AuthCodeOption, 0)
	if h.options.AccessType != "" {
		authCodeOpt = append(authCodeOpt, oauth2.SetAuthURLParam("access_type", h.options.AccessType))
	}
	sess.Values[refererSessKey] = req.URL.String()
	err = sess.Save(req, w)
	if err != nil {
		panic(err)
	}
	authUrl := h.oauth2Conf.AuthCodeURL(stateCode, authCodeOpt...)
	http.Redirect(w, req, authUrl, 302)
	return
}
func (h Oauth2Handler) serveNext(w http.ResponseWriter, req *http.Request, sess *sessions.Session) {
	if h.reqHasToken(req) {
		sess.Values[tokenSessKey] = h.reqToken(req)
		sess.Save(req, w)
	}
	if h.sessionHasToken(sess) {
		req.Header.Set("Authorization", sess.Values[tokenSessKey].(string))
	}
	if sess.Values["username"] != nil {
		gobis.SetUsername(req, sess.Values["username"].(string))
		h.next.ServeHTTP(w, req)
		return
	}
	token := sess.Values[tokenSessKey].(string)
	tokenSplit := strings.Split(token, " ")
	tokenType := ""
	if len(tokenSplit) > 1 {
		tokenType = tokenSplit[0]
		token = strings.Join(tokenSplit[1:], " ")
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.client)
	req.Header.Set("Authorization", sess.Values[tokenSessKey].(string))
	h.retrieveUserInfo(req, ctx, &oauth2.Token{
		TokenType:   tokenType,
		AccessToken: token,
	})
	sess.Values["username"] = gobis.Username(req)
	sess.Save(req, w)
	h.next.ServeHTTP(w, req)
}
func (h Oauth2Handler) LogoutHandler(w http.ResponseWriter, req *http.Request) {
	sess, err := h.getSession(req)
	if err != nil {
		panic(err)
	}
	sess.Options.MaxAge = -1
	err = sess.Save(req, w)
	if err != nil {
		panic(err)
	}
	redirectUrl := h.options.RedirectLogUrl
	if redirectUrl == "" {
		redirectUrl = req.Referer()
	}
	if redirectUrl == "" {
		w.Write([]byte("Successfully logout"))
		return
	}
	http.Redirect(w, req, redirectUrl, 302)
	return
}
func (h Oauth2Handler) LoginHandler(w http.ResponseWriter, req *http.Request) {
	if h.options.UseRedirectUrl {
		h.oauth2Conf.RedirectURL = h.callbackCreateFunc(req).String()
	}
	sess, err := h.getSession(req)
	if err != nil {
		panic(err)
	}
	code := req.URL.Query().Get("code")
	if code == "" {
		http.Error(w, http.StatusText(401)+": no code provided", 401)
		return
	}
	state := req.URL.Query().Get("state")
	if state != sess.Values[stateSessKey].(string) {
		http.Error(w, http.StatusText(401)+": bad state", 401)
		return
	}
	if len(sess.Values) == 0 {
		http.Error(w, http.StatusText(401)+": no session exists", 401)
		return
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.client)
	token, err := h.oauth2Conf.Exchange(ctx, code)
	if err != nil {
		panic(err)
	}
	delete(sess.Values, stateSessKey)
	sess.Options.MaxAge = token.Expiry.Second()
	tokenStr := token.TokenType + " " + token.AccessToken
	req.Header.Set("Authorization", tokenStr)
	sess.Values[tokenSessKey] = tokenStr

	gobis.AddGroups(req, h.options.Scopes...)
	h.retrieveUserInfo(req, ctx, token)
	sess.Values["username"] = gobis.Username(req)
	redirectUrl := h.options.RedirectLogUrl
	if redirectUrl == "" && sess.Values[refererSessKey] != nil {
		redirectUrl = sess.Values[refererSessKey].(string)
		delete(sess.Values, refererSessKey)
	}
	err = sess.Save(req, w)
	if err != nil {
		panic(err)
	}
	if redirectUrl == "" {
		redirectUrl = req.Referer()
	}
	if redirectUrl == "" {
		w.Write([]byte("Successfully logged in"))
		return
	}
	http.Redirect(w, req, redirectUrl, 302)
	return
}
func (h Oauth2Handler) retrieveUserInfo(req *http.Request, ctx context.Context, token *oauth2.Token) {
	if h.options.UserInfoUri == "" {
		return
	}
	c := h.oauth2Conf.Client(ctx, token)
	userReq, err := http.NewRequest("GET", h.options.UserInfoUri, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Accept", "application/json")
	resp, err := c.Do(userReq)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := ioutil.ReadAll(resp.Body)
		panic(fmt.Sprintf("Error when retrieving user information %d: %s", resp.StatusCode, string(b)))
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Error when retrieving user information: %s", err.Error()))
	}
	userInfo := make(map[string]interface{})
	err = json.Unmarshal(b, &userInfo)
	if err != nil {
		panic(fmt.Sprintf("Error when retrieving user information: %s", err.Error()))
	}
	usrRegex := regexp.MustCompile("(?i)^(user|username|user_name|user_id)$")
	for key, value := range userInfo {
		if usrRegex.MatchString(key) {
			gobis.SetUsername(req, fmt.Sprint(value))
		}
	}
	if email, ok := userInfo["email"]; ok && gobis.Username(req) == "" {
		gobis.SetUsername(req, fmt.Sprint(email))
	}
	if login, ok := userInfo["login"]; ok && gobis.Username(req) == "" {
		gobis.SetUsername(req, fmt.Sprint(login))
	}
}
func createSessStore(authKey, encKey string) *sessions.CookieStore {
	keyPairs := [][]byte{
		[]byte(authKey),
	}
	if encKey != "" {
		keyPairs = append(keyPairs, []byte(encKey))
	}
	return sessions.NewCookieStore(keyPairs...)
}
func createOauth2Conf(options *Oauth2Options) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     options.ClientId,
		ClientSecret: options.ClientSecret,
		Scopes:       options.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  options.AuthorizationUri,
			TokenURL: options.AccessTokenUri,
		},
	}
}
