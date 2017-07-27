package middlewares

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/basic2token"
	"github.com/orange-cloudfoundry/gobis-middlewares/basicauth"
	"github.com/orange-cloudfoundry/gobis-middlewares/trace"
	"github.com/orange-cloudfoundry/gobis-middlewares/connlimit"
	"github.com/orange-cloudfoundry/gobis-middlewares/ratelimit"
	"github.com/orange-cloudfoundry/gobis-middlewares/cbreaker"
	"github.com/orange-cloudfoundry/gobis-middlewares/casbin"
	"github.com/orange-cloudfoundry/gobis-middlewares/jwt"
	"github.com/orange-cloudfoundry/gobis-middlewares/oauth2"
	"github.com/orange-cloudfoundry/gobis-middlewares/ldap"
	"github.com/orange-cloudfoundry/gobis-middlewares/cors"
	"github.com/orange-cloudfoundry/gobis-middlewares/authpubtkt"
)

func DefaultHandlers() []gobis.MiddlewareHandler {
	return []gobis.MiddlewareHandler{
		cors.NewCors(),
		ldap.NewLdap(),
		basicauth.NewBasicAuth(),
		basic2token.NewBasic2Token(),
		oauth2.NewOauth2(),
		authpubtkt.NewAuthPubTkt(),
		jwt.NewJwt(),
		casbin.NewCasbin(),
		cbreaker.NewCircuitBreaker(),
		ratelimit.NewRateLimit(),
		connlimit.NewConnLimit(),
		trace.NewTrace(),

	}
}

