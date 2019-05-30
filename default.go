package middlewares

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/authpubtkt"
	"github.com/orange-cloudfoundry/gobis-middlewares/basic2token"
	"github.com/orange-cloudfoundry/gobis-middlewares/basicauth"
	"github.com/orange-cloudfoundry/gobis-middlewares/casbin"
	"github.com/orange-cloudfoundry/gobis-middlewares/cbreaker"
	"github.com/orange-cloudfoundry/gobis-middlewares/ceftrace"
	"github.com/orange-cloudfoundry/gobis-middlewares/cf_checkpermission"
	"github.com/orange-cloudfoundry/gobis-middlewares/connlimit"
	"github.com/orange-cloudfoundry/gobis-middlewares/cors"
	"github.com/orange-cloudfoundry/gobis-middlewares/infopage"
	"github.com/orange-cloudfoundry/gobis-middlewares/jwt"
	"github.com/orange-cloudfoundry/gobis-middlewares/ldap"
	"github.com/orange-cloudfoundry/gobis-middlewares/oauth2"
	"github.com/orange-cloudfoundry/gobis-middlewares/oauth2request"
	"github.com/orange-cloudfoundry/gobis-middlewares/ratelimit"
	"github.com/orange-cloudfoundry/gobis-middlewares/secure"
	"github.com/orange-cloudfoundry/gobis-middlewares/trace"
)

// Provide all middleware as a single function
// Order do matter !
// Middleware call are made in order and middleware for security should be called first.
func DefaultHandlers() []gobis.MiddlewareHandler {
	return []gobis.MiddlewareHandler{
		cors.NewCors(),
		secure.NewSecure(),
		basicauth.NewBasicAuth(),
		ldap.NewLdap(),
		basic2token.NewBasic2Token(),
		oauth2.NewOauth2(),
		authpubtkt.NewAuthPubTkt(),
		jwt.NewJwt(),
		casbin.NewCasbin(),
		cf_checkpermission.NewCfCheckPermission(),
		cbreaker.NewCircuitBreaker(),
		ratelimit.NewRateLimit(),
		connlimit.NewConnLimit(),
		infopage.NewInfoPage(),
		oauth2request.NewOauth2Request(),
		ceftrace.NewCefTrace(),
		trace.NewTrace(),
	}
}
