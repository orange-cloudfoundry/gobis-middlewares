package pubtkt

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	ticketKey AuthPubTktContextKey = iota
)

type AuthPubTktContextKey int
type AuthPubTktHandler struct {
	auth                 AuthPubTkt
	options              AuthPubTktOptions
	next                 http.Handler
	panicOnError         bool
	showErrorDetails     bool
	statusText           string
	statusCode           int
	createAuthPubTktFunc func(options AuthPubTktOptions) AuthPubTkt
}

func NewAuthPubTktHandler(options AuthPubTktOptions, next http.Handler, handlerOpts ...AuthPubTktHandlerOption) (*AuthPubTktHandler, error) {
	var err error
	if options.TKTAuthHeader == nil || len(options.TKTAuthHeader) == 0 {
		options.TKTAuthHeader = []string{"Cookie"}
	}
	if options.TKTAuthCookieName == "" {
		options.TKTAuthCookieName = "auth_pubtkt"
	}
	if options.TKTAuthBackArgName == "" {
		options.TKTAuthBackArgName = "back"
	}
	if options.TKTAuthLoginURL == "" {
		return nil, fmt.Errorf("option TKTAuthLoginURL cannot be omitted")
	}
	if options.TKTAuthTimeoutURL == "" {
		options.TKTAuthTimeoutURL = options.TKTAuthLoginURL
	}
	if options.TKTAuthPostTimeoutURL == "" {
		options.TKTAuthPostTimeoutURL = options.TKTAuthLoginURL
	}
	if options.TKTAuthUnauthURL == "" {
		options.TKTAuthUnauthURL = options.TKTAuthLoginURL
	}
	if options.TKTAuthRefreshURL == "" {
		options.TKTAuthRefreshURL = options.TKTAuthLoginURL
	}
	handler := &AuthPubTktHandler{
		options:    options,
		next:       next,
		statusText: http.StatusText(http.StatusForbidden),
		statusCode: http.StatusForbidden,
	}
	for _, s := range handlerOpts {
		err = s(handler)
		if err != nil {
			return nil, err
		}
	}

	if handler.auth == nil {
		handler.auth, err = NewAuthPubTkt(options)
		if err != nil {
			return nil, err
		}
	}
	return handler, nil
}
func (h AuthPubTktHandler) forgeRedirect(redirectUrl string, w http.ResponseWriter, req *http.Request) {
	redirect, _ := url.Parse(redirectUrl)
	query := redirect.Query()
	requestUrl := req.URL.String()
	if !req.URL.IsAbs() {
		scheme := "http://"
		if req.TLS != nil {
			scheme = "https://"
		}
		requestUrl = scheme + strings.Split(req.Host, ":")[0] + requestUrl
	}
	query.Add(h.options.TKTAuthBackArgName, requestUrl)
	redirect.RawQuery = query.Encode()
	http.Redirect(w, req, redirect.String(), 302)
}
func (h AuthPubTktHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ticket, err := h.auth.VerifyFromRequest(req)
	if err == nil {
		setTicket(ticket, req)
		err := h.WriteBasicAuth(ticket, req)
		if err != nil {
			h.writeErr(err, w)
			return
		}
		h.next.ServeHTTP(w, req)
		return
	}
	_, isSigNotValid := err.(ErrSigNotValid)
	_, isNoTicket := err.(ErrNoTicket)
	_, isValidExp := err.(ErrValidationExpired)
	_, isGraceExp := err.(ErrGracePeriodExpired)
	_, isNoToken := err.(ErrNoValidToken)
	if isSigNotValid || isNoTicket {
		h.forgeRedirect(h.options.TKTAuthLoginURL, w, req)
		return
	}
	if isValidExp && req.Method == "POST" {
		h.forgeRedirect(h.options.TKTAuthPostTimeoutURL, w, req)
		return
	}
	if isValidExp {
		h.forgeRedirect(h.options.TKTAuthTimeoutURL, w, req)
		return
	}
	if isGraceExp {
		h.forgeRedirect(h.options.TKTAuthRefreshURL, w, req)
		return
	}
	if isNoToken {
		h.forgeRedirect(h.options.TKTAuthUnauthURL, w, req)
		return
	}
	h.writeErr(err, w)
	return
}

func (h AuthPubTktHandler) WriteBasicAuth(ticket *Ticket, req *http.Request) error {
	if !h.options.TKTAuthFakeBasicAuth && !h.options.TKTAuthPassthruBasicAuth {
		return nil
	}
	if h.options.TKTAuthFakeBasicAuth {
		req.SetBasicAuth(ticket.Uid, "password")
		return nil
	}
	if h.options.TKTAuthPassthruBasicKey == "" {
		req.Header.Set("Authorization", ticket.Bauth)
		return nil
	}
	bauthDecrypted, err := BauthDecrypt(ticket.Bauth, h.options.TKTAuthPassthruBasicKey)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", bauthDecrypted)
	return nil
}

func (h AuthPubTktHandler) writeErr(err error, w http.ResponseWriter) {
	if h.panicOnError {
		panic(err)
		return
	}
	statusText := h.statusText
	if h.showErrorDetails {
		statusText += "\nError details: " + err.Error()
	}
	w.WriteHeader(h.statusCode)
	w.Write([]byte(statusText))
}
func TicketRequest(req *http.Request) *Ticket {
	ticketCtx := req.Context().Value(ticketKey)
	if ticketCtx == nil {
		return nil
	}
	return ticketCtx.(*Ticket)
}

func setTicket(ticket *Ticket, req *http.Request) {
	ticketCtx := req.Context().Value(ticketKey)
	if ticketCtx == nil {
		ctxValueReq := req.WithContext(context.WithValue(req.Context(), ticketKey, ticket))
		*req = *ctxValueReq
		return
	}
	ticketCtxDec := ticketCtx.(*Ticket)
	*ticketCtxDec = *ticket
}

type AuthPubTktHandlerOption func(*AuthPubTktHandler) error

// If used unrecognized error send a panic instead
func PanicOnError() AuthPubTktHandlerOption {
	return func(h *AuthPubTktHandler) error {
		h.panicOnError = true
		return nil
	}
}

// If used error details will be write in request response
func ShowErrorDetails() AuthPubTktHandlerOption {
	return func(h *AuthPubTktHandler) error {
		h.showErrorDetails = true
		return nil
	}
}

// Customize status text and status code when an unrecognized error occurred in request responqe
func SetStatus(statusText string, statusCode int) AuthPubTktHandlerOption {
	return func(h *AuthPubTktHandler) error {
		h.statusText = statusText
		h.statusCode = statusCode
		return nil
	}
}
func SetCreateAuthPubTktFunc(fn func(options AuthPubTktOptions) (AuthPubTkt, error)) AuthPubTktHandlerOption {
	return func(h *AuthPubTktHandler) error {
		var err error
		h.auth, err = fn(h.options)
		if err != nil {
			return err
		}
		return nil
	}
}
