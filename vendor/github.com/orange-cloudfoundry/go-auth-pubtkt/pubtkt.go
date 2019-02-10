package pubtkt

import (
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AuthPubTkt interface {
	// Verify ticket and pre-check from a request
	VerifyFromRequest(*http.Request) (*Ticket, error)
	// Transform a request to a ticket (if found)
	RequestToTicket(*http.Request) (*Ticket, error)
	// Transform an encoded ticket or plain ticket as a ticket strcture
	RawToTicket(ticketStr string) (*Ticket, error)
	// Verify a ticket with signature, expiration, token (if set) and ip (against the provided ip and if TKTCheckIpEnabled option is true)
	VerifyTicket(ticket *Ticket, clientIp string) error
}
type AuthPubTktImpl struct {
	options AuthPubTktOptions
	openSSL *OpenSSL
}

var TimeNowFunc = func() time.Time {
	return time.Now()
}

func NewAuthPubTkt(options AuthPubTktOptions) (AuthPubTkt, error) {
	if options.TKTAuthPublicKey == "" {
		return nil, fmt.Errorf("TKTAuthPublicKey must be set")
	}
	if options.TKTAuthCookieName == "" {
		return nil, fmt.Errorf("TKTAuthCookieName must be set")
	}
	if options.TKTAuthHeader == nil || len(options.TKTAuthHeader) == 0 {
		return nil, fmt.Errorf("TKTAuthHeader must be set")
	}
	return &AuthPubTktImpl{options, NewOpenSSL()}, nil
}
func (a AuthPubTktImpl) VerifyFromRequest(req *http.Request) (*Ticket, error) {
	if req.TLS == nil && a.options.TKTAuthRequireSSL {
		return nil, NewErrNoSSl()
	}
	ip := strings.Split(req.RemoteAddr, ":")[0]
	if a.options.TKTCheckXForwardedIp {
		xffClient := strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-For"), ",")[0])
		ip = strings.Split(xffClient, ":")[0]
	}
	ticket, err := a.RequestToTicket(req)
	if err != nil {
		return nil, err
	}
	err = a.VerifyTicket(ticket, ip)
	if err != nil {
		return nil, err
	}
	return ticket, nil
}
func (a AuthPubTktImpl) RequestToTicket(req *http.Request) (*Ticket, error) {
	var content string
	for _, header := range a.options.TKTAuthHeader {
		header = strings.ToLower(header)
		if header != "cookie" {
			content = req.Header.Get(header)
			if content == "" {
				continue
			}
		}
		cookie, err := req.Cookie(a.options.TKTAuthCookieName)
		if err != nil {
			continue
		}
		content = cookie.Value
		break
	}
	if content == "" {
		return nil, NewErrNoTicket()
	}
	content, err := url.QueryUnescape(content)
	if err != nil {
		return nil, err
	}
	return a.RawToTicket(content)
}
func (a AuthPubTktImpl) RawToTicket(ticketStr string) (*Ticket, error) {
	var err error
	if a.options.TKTCypherTicketsWithPasswd != "" {
		ticketStr, err = a.decrypt(ticketStr)
		if err != nil {
			return nil, err
		}
	}
	return ParseTicket(ticketStr)
}

func (a AuthPubTktImpl) VerifyTicket(ticket *Ticket, clientIp string) error {
	err := a.verifySignature(ticket)
	if err != nil {
		return err
	}
	err = a.verifyToken(ticket)
	if err != nil {
		return err
	}
	err = a.verifyIp(ticket, clientIp)
	if err != nil {
		return err
	}
	err = a.verifyExpiration(ticket)
	if err != nil {
		return err
	}
	return nil
}
func (a AuthPubTktImpl) verifyIp(ticket *Ticket, ip string) error {
	if !a.options.TKTCheckIpEnabled || ticket.Cip == "" {
		return nil
	}
	if ticket.Cip != ip {
		return NewErrWrongIp()
	}
	return nil
}
func (a AuthPubTktImpl) verifyToken(ticket *Ticket) error {
	if a.options.TKTAuthToken == nil || len(a.options.TKTAuthToken) == 0 {
		return nil
	}
	tokTicketMap := make(map[string]bool)
	for _, tok := range ticket.Tokens {
		tokTicketMap[tok] = true
	}
	for _, tok := range a.options.TKTAuthToken {
		if _, ok := tokTicketMap[tok]; ok {
			return nil
		}
	}
	return NewErrNoValidToken()
}
func (a AuthPubTktImpl) verifyExpiration(ticket *Ticket) error {
	if !ticket.Validuntil.IsZero() && TimeNowFunc().After(ticket.Validuntil) {
		return NewErrValidationExpired()
	}
	if !ticket.Graceperiod.IsZero() && TimeNowFunc().After(ticket.Graceperiod) {
		return NewErrGracePeriodExpired()
	}
	return nil
}
func (a AuthPubTktImpl) verifySignature(ticket *Ticket) error {
	authDigest := strings.ToLower(a.options.TKTAuthDigest)
	if a.options.TKTAuthDigest == "" || authDigest == "dss1" {
		err := a.verifyDsaSignature(ticket)
		if err == nil || authDigest == "dss1" {
			return err
		}
	}
	return a.verifyRsaSignature(ticket)
}
func (a AuthPubTktImpl) verifyDsaSignature(ticket *Ticket) error {
	block, _ := pem.Decode([]byte(a.options.TKTAuthPublicKey))
	if block == nil {
		return fmt.Errorf("no TKTAuthPublicKey found")
	}
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Error when parse public key: %s", err.Error())
	}
	pub, isDsa := cert.(*dsa.PublicKey)
	if !isDsa {
		return fmt.Errorf("not a DSA Key")
	}

	certif := x509.Certificate{
		PublicKey: pub,
	}
	signature, _ := base64.StdEncoding.DecodeString(ticket.Sig)
	err = certif.CheckSignature(x509.DSAWithSHA1, []byte(ticket.DataString()), signature)
	if err != nil {
		return NewErrSigNotValid(err)
	}
	return nil
}
func (a AuthPubTktImpl) verifyRsaSignature(ticket *Ticket) error {
	block, _ := pem.Decode([]byte(a.options.TKTAuthPublicKey))
	if block == nil {
		return fmt.Errorf("no TKTAuthPublicKey found")
	}
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Error when parse public key: %s", err.Error())
	}
	pub, isRsa := cert.(*rsa.PublicKey)
	if !isRsa {
		return fmt.Errorf("not a RSA Key")
	}
	ds, _ := base64.StdEncoding.DecodeString(ticket.Sig)
	authDigest := a.options.TKTAuthDigest
	if authDigest == "" {
		authDigest = "sha1"
	}
	hash, cryptoHash, err := FindHash(authDigest)
	if err != nil {
		return fmt.Errorf("Error when finding hash: %s", err.Error())
	}
	hash.Write([]byte(ticket.DataString()))
	digest := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(pub, cryptoHash, digest, ds)
	if err != nil {
		return NewErrSigNotValid(err)
	}
	return nil
}
func (a AuthPubTktImpl) decrypt(encTkt string) (string, error) {
	data, err := a.openSSL.DecryptString(
		a.options.TKTCypherTicketsWithPasswd,
		encTkt,
		EncMethod(strings.ToUpper(a.options.TKTCypherTicketsMethod)))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
