package casbin

import (
	"github.com/casbin/casbin"
	"github.com/casbin/casbin/persist"
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
	"strings"
	log "github.com/sirupsen/logrus"
)

type CasbinHandler struct {
	next         http.Handler
	casbinOption *CasbinOption
}

func NewCasbinHandler(next http.Handler, casbinOption *CasbinOption) http.Handler {
	return &CasbinHandler{next, casbinOption}
}

func (h CasbinHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	gobisAdapter := NewGobisAdapter()
	gobisAdapter.AddPolicies(h.casbinOption.Policies...)
	gobisAdapter.AddPoliciesFromRequest(req)
	enforcer := newEnforcer(gobisAdapter, h.casbinOption.PermConf)
	if !h.CheckPermission(enforcer, req) {
		http.Error(w, http.StatusText(403), 403)
		return
	}

	h.next.ServeHTTP(w, req)
}



// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (h CasbinHandler) CheckPermission(e *casbin.Enforcer, r *http.Request) bool {
	user := gobis.Username(r)
	method := r.Method
	path := gobis.Path(r)
	path = strings.TrimSuffix(path, "/") + "/"
	return e.Enforce(user, path, method)
}

func newEnforcer(adapter persist.Adapter, modelConfText string) *casbin.Enforcer {
	if modelConfText == "" {
		modelConfText = MODEL_CONF
	}
	modelConf := casbin.NewModel()
	modelConf.LoadModelFromText(modelConfText)
	enableLog := log.GetLevel() == log.DebugLevel
	return casbin.NewEnforcer(modelConf, adapter, enableLog)
}

type Casbin struct{}

func NewCasbin() *Casbin {
	return &Casbin{}
}
func (Casbin) Handler(proxyRoute gobis.ProxyRoute, params interface{}, handler http.Handler) (http.Handler, error) {
	config := params.(CasbinConfig)
	if config.Casbin == nil || !config.Casbin.Enabled {
		return handler, nil
	}
	return NewCasbinHandler(handler, config.Casbin), nil
}
func (Casbin) Schema() interface{} {
	return CasbinConfig{}
}