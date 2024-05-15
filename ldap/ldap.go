package ldap

import (
	"crypto/tls"
	"fmt"
	"github.com/goji/httpauth"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"gopkg.in/ldap.v2"
	"net/http"
	"os"
)

const (
	LDAP_BIND_DN_KEY       = "LDAP_BIND_DN"
	LDAP_BIND_PASSWORD_KEY = "LDAP_BIND_PASSWORD"
	LDAP_BIND_ADDRESS      = "LDAP_BIND_ADDRESS"
)

type LdapConfig struct {
	Ldap *LdapOptions `mapstructure:"ldap" json:"ldap" yaml:"ldap"`
}
type LdapOptions struct {
	// Enabled enable LDAP basic auth middleware
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// BindDn Search user bind dn (Can be set by env var `LDAP_BIND_DN`)
	BindDn string `mapstructure:"bind_dn" json:"bind_dn" yaml:"bind_dn"`
	// BindPassword Search user bind password (Can be set by env var `LDAP_BIND_PASSWORD`)
	BindPassword string `mapstructure:"bind_password" json:"bind_password" yaml:"bind_password"`
	// Address LDAP server address in the form of host:port (Can be set by env var `LDAP_BIND_ADDRESS`)
	Address string `mapstructure:"address" json:"address" yaml:"address"`
	// UseSsl Set to true if ldap server supports TLS
	UseSsl bool `mapstructure:"use_ssl" json:"use_ssl" yaml:"use_ssl"`
	// InsecureSkipVerify Set to true to skip certificate check (NOT RECOMMENDED)
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	// SearchBaseDns base dns to search through (Default: `dc=com`)
	SearchBaseDns string `mapstructure:"search_base_dns" json:"search_base_dns" yaml:"search_base_dns"`
	// SearchFilter User search filter, for example "(cn=%s)" or "(sAMAccountName=%s)" or "(uid=%s)" (default: `(objectClass=organizationalPerson)&(uid=%s)`)
	SearchFilter string `mapstructure:"search_filter" json:"search_filter" yaml:"search_filter"`
	// GroupSearchFilter Group search filter, to retrieve the groups of which the user is a member
	// Groups will be passed in request context as a list of strings, how to retrieve: ctx.Groups(*http.Request)
	// if GroupSearchFilter or GroupSearchBaseDns or MemberOf are empty it will not search for groups
	GroupSearchFilter string `mapstructure:"group_search_filter" json:"group_search_filter" yaml:"group_search_filter"`
	// GroupSearchBaseDns base DNs to search through for groups
	GroupSearchBaseDns string `mapstructure:"group_search_base_dns" json:"group_search_base_dns" yaml:"group_search_base_dns"`
	// MemberOf Search group name by this value (default: `memberOf`)
	MemberOf string `mapstructure:"member_of" json:"member_of" yaml:"member_of"`
	// TrustCurrentUser Passthrough if a previous middleware already set user context
	// This is helpful when you want to add a user with basic auth middleware
	TrustCurrentUser bool `mapstructure:"trust_current_user" json:"trust_current_user" yaml:"trust_current_user"`
}
type LdapAuth struct {
	LdapOptions
}

func NewLdapAuth(opt LdapOptions) *LdapAuth {
	return &LdapAuth{opt}
}
func (l LdapAuth) CreateConn() (conn *ldap.Conn, err error) {
	if l.UseSsl {
		conn, err = ldap.DialTLS("tcp", l.Address, &tls.Config{InsecureSkipVerify: l.InsecureSkipVerify})
	} else {
		conn, err = ldap.Dial("tcp", l.Address)
	}
	if err != nil {
		return
	}
	err = conn.Bind(l.BindDn, l.BindPassword)
	if err != nil {
		return
	}
	return
}
func (l LdapAuth) LdapAuth(user, password string, req *http.Request) bool {
	if l.LdapOptions.TrustCurrentUser && gobis.Username(req) != "" {
		return true
	}
	gobis.DirtHeader(req, "Authorization")
	conn, err := l.CreateConn()
	if err != nil {
		panic(fmt.Sprintf("orange-cloudfoundry/gobis/middlewares: invalid ldap for '%s': %s", l.Address, err.Error()))
	}
	defer conn.Close()
	searchRequest := ldap.NewSearchRequest(
		l.SearchBaseDns,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&"+l.SearchFilter+")", user),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		panic(fmt.Sprintf("orange-cloudfoundry/gobis/middlewares: invalid ldap search for '%s': %s", l.Address, err.Error()))
	}

	if len(sr.Entries) != 1 {
		return false
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = conn.Bind(userdn, password)
	if err != nil {
		return false
	}
	err = l.LoadLdapGroup(user, conn, req)
	if err != nil {
		panic(fmt.Sprintf("orange-cloudfoundry/gobis/middlewares: invalid ldap group search for '%s': %s", l.Address, err.Error()))
	}
	gobis.SetUsername(req, user)
	return true
}
func (l LdapAuth) LoadLdapGroup(user string, conn *ldap.Conn, req *http.Request) error {
	if l.GroupSearchBaseDns == "" || l.GroupSearchFilter == "" {
		return nil
	}
	searchRequest := ldap.NewSearchRequest(
		l.GroupSearchBaseDns,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&"+l.GroupSearchFilter+")", user),
		[]string{l.MemberOf},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return err
	}
	groups := make([]string, 0)

	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue(l.MemberOf))
	}
	gobis.AddGroups(req, groups...)
	return nil
}

type Ldap struct{}

func NewLdap() *Ldap {
	return &Ldap{}
}
func (Ldap) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(LdapConfig)
	options := config.Ldap
	if options == nil || !options.Enabled {
		return handler, nil
	}
	err := utils.RequiredVal(
		options.BindDn, "bind dn",
		options.BindPassword, "bind password",
		options.Address, "address",
	)
	if err != nil {
		return handler, err
	}
	if options.BindDn == "" {
		options.BindDn = os.Getenv(LDAP_BIND_DN_KEY)
	}
	if options.BindPassword == "" {
		options.BindPassword = os.Getenv(LDAP_BIND_PASSWORD_KEY)
	}
	if options.Address == "" {
		options.Address = os.Getenv(LDAP_BIND_ADDRESS)
	}
	if options.SearchBaseDns == "" {
		options.SearchBaseDns = "dc=com"
	}
	if options.SearchFilter == "" {
		options.SearchFilter = "(objectClass=organizationalPerson)&(uid=%s)"
	}
	if options.MemberOf == "" {
		options.MemberOf = "memberOf"
	}
	ldapAuth := NewLdapAuth(*options)
	return httpauth.BasicAuth(httpauth.AuthOptions{
		AuthFunc: ldapAuth.LdapAuth,
	})(handler), nil
}
func (Ldap) Schema() interface{} {
	return LdapConfig{}
}
