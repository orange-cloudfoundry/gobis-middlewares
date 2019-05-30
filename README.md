# Gobis-middlewares [![GoDoc](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares?status.svg)](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares)

This is a set of middlewares created for [gobis](https://github.com/orange-cloudfoundry/gobis) useable on your on project containing gobis.

**Note**: They are loaded by default on [gobis-server](https://github.com/orange-cloudfoundry/gobis-server)

List:
- [basic2token](#basic2token): Give the ability to connect an user over basic auth, retrieve a token from an oauth2 server with user information and forward the request with this token.
- [basic auth](#basic-auth)
- [casbin](#casbin): An authorization library that supports access control models like ACL, RBAC, ABAC
- [cef trace](#cef-trace): Produce access log in CEF format for siem.
- [cf check permission](#cf-check-permission): Check if user has access to a service instance on a cloud foundry platform.
- [circuit breaker](#circuit-breaker)
- [conn limit](#conn-limit)
- [cors](#cors)
- [infopage](#infopage): Add an endpoint on upstream to see information like headers set by gobis and user informations set by middlewares (Useful for frontend)
- [JWT](#jwt)
- [oauth2](#oauth2)
- [oauth2request](#oauth2request)
- [ldap](#ldap)
- [secure](#secure): An HTTP middleware for Go that facilitates some quick security wins
- [rate limit](#rate-limit)
- [trace](#trace)

**Pro tip**:

You can set multiple middleware params programmatically by using a dummy structure containing each config you wanna set, example:
```go
package main
import (
    "github.com/orange-cloudfoundry/gobis-middlewares/trace"
    "github.com/orange-cloudfoundry/gobis-middlewares/cors"
    "github.com/orange-cloudfoundry/gobis"
)
func main(){
    configHandler := gobis.DefaultHandlerConfig{
            Routes: []gobis.ProxyRoute{
                {
                    Name: "myapi",
                    Path: "/app/**",
                    Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                    MiddlewareParams: struct {
                        trace.TraceConfig
                        cors.CorsConfig
                    }{
                        TraceConfig: trace.TraceConfig{
                            Trace: &trace.TraceOptions{
                                Enabled: true,
                            },
                        },
                        CorsConfig: cors.CorsConfig{
                            Cors: &cors.CorsOptions{
                                Enabled: true,
                            },
                        },
                    },
                },
            },
    }
    gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(trace.NewTrace(), cors.NewCors()))
}
```

## Basic2Token

Give the ability to connect an user over basic auth, retrieve a token from an oauth2 server with user information and forward the request with this token.

This was made to transparently convert a basic auth authentication to an oauth2 one.

See godoc for [Basic2TokenOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/basic2token#Basic2TokenOptions) to know more about parameters.

**Note**:
- Your oauth2 server must have the `password` grant type such as [UAA](https://github.com/cloudfoundry/uaa) or [Gitlab in oauth2 provider](https://docs.gitlab.com/ce/api/oauth2.html#resource-owner-password-credentials)

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/basic2token"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: basic2token.Basic2TokenConfig{
                        Ldap: &basic2token.Basic2TokenOptions{
                                Enable: true,
                                AccessTokenUri: "https://my.uaa.local/oauth/token",
                                ClientId: "cf",
                                ClientSecret: "",
                                ParamsAsJson: false,
                                UseRouteTransport: true,
                                InsecureSkipVerify: true,
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(basic2token.NewBasic2Token()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  basic2token:
    enabled: true
    access_token_uri: https://my.uaa.local/oauth/token
    client_id: cf
    client_secret: ~
    params_as_json: false
    use_route_transport: false
    insecure_skip_verify: true
```

### Tips

- If key `scope` is found in the response of the oauth2 server, thoses scopes will be loaded as groups and others middlewares will
 be able to find groups for the current user by using [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups)
- Logged user is accessible by other middleware through [context username](https://godoc.org/github.com/orange-cloudfoundry/gobis#Username)

### Credits

- https://github.com/goji/httpauth

## Basic auth

Add basic auth to upstream

See godoc for [BasicAuthOption](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/basicauth#BasicAuthOption) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/basicauth"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: basicauth.BasicAuthConfig{
                        BasicAuth: &basicauth.BasicAuthOptions{
                                {
                                        User: "user",
                                        Password: "$2y$12$AHKssZrkmcG2pmom.rvy2OMsV8HpMHHcRIEY158LgZIkrA0BFvFQq", // equal password
                                        Crypted: true, // hashed by bcrypt, you can use https://github.com/gibsjose/bcrypt-hash command to crypt a password
                                },
                                {
                                        User: "user2",
                                        Password: "mypassword",
                                        Groups: []string{"admin"}
                                },
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(basicauth.NewBasicAuth()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  basic_auth:
  - user: user
    password: $2y$12$AHKssZrkmcG2pmom.rvy2OMsV8HpMHHcRIEY158LgZIkrA0BFvFQq # equal password
    crypted: true # hashed by bcrypt, you can use https://github.com/gibsjose/bcrypt-hash command to crypt a password
  - user: user2
    password: mypassword # equal password
    groups: [admin]
```

### Tips

- By setting groups it will allow others middleware to find groups for the current user by using [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups)
- If you use bcrypt more the cost will be higher more it will take time to test a password against it and will increase response time

### Credits

- https://github.com/goji/httpauth


## Casbin

[casbin](https://github.com/casbin/casbin) is an authorization library that supports access control models like ACL, RBAC, ABAC.

This middleware allow you to add access control over your apo

See godoc for [CasbinOption](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/casbin#CasbinOption) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/casbin"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: casbin.CasbinConfig{
                        CircuitBreaker: &casbin.CasbinOption{
                                Enabled: true,
                                Policies: []casbin.CasbinPolicy{
                                        Type: "p",
                                        Sub: "usernameOrGroupName",
                                        Obj: "/mysubpath/*"
                                        Act: "*",
                                },
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(casbin.NewCasbin()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  casbin:
    enabled: true
    policies:
    - {type: p, sub: usernameOrGroupName, obj: /mysubpath/*, act: *}
```

### Tips

- It will load as role policies all groups found by using [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups)
this allow you, if you use ldap middleware, to pass a group name found as a `sub` (e.g.: `sub: myUserGroupName`)
- It will also load all policies found in context key `casbin.PolicyContextKey` this allow other middleware to add their own policies

### Credits

- https://github.com/casbin/casbin

## CEF Trace

Produce access log in CEF format for siem.

See godoc for [CefTraceOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/ceftrace#CefTraceOptions) to know more about parameters.

Trace will take the form:
`CEF:0|device_vendor|device_product|device_version|my-sig|GET /path/request|0|rt=<unix timestamp> request=/path/request requestMethod=GET httpStatusCode=200 src=10.0.0.1 suser=user-gobis sgroups=group,gobis xForwardedFor=10.0.0.2`

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/ceftrace"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: cf_checkpermission.CfCheckPermissionConfig{
                        CefTrace: &ceftrace.CefTraceOptions{
                                Enabled: true,
                                DeviceVendor: "device_vendor",
                                DeviceProduct: "device_product",
                                DeviceVersion: "device_version",
                                KeySignatureID: "my-sig",
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(ceftrace.NewCefTrace()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  cef_trace:
    enabled: true
    device_vendor: device_vendor
    device_product: device_product
    device_version: device_version
    key_signature_id: my-sig
```

## Cf check permission

Check if user has access to a service instance on a cloud foundry platform.

See godoc for [CorsOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/cf_checkpermission#CfCheckPermissionOptions) to know more about parameters.

**You must use this middleware with [oauth2](#oauth2) middleware, client must have scope `cloud_controller_service_permissions.read`**

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/cf_checkpermission"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: cf_checkpermission.CfCheckPermissionConfig{
                        Cors: &cf_checkpermission.CfCheckPermissionOptions{
                                Enabled: true,
                                ApiEndpoint: "https://api.my.cloudfoundry",
                                InstanceGUID: "service-instance-guid",
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(cors.NewCors()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  cf_checkpermission:
    enabled: true
    api_endpoint: https://api.my.cloudfoundry
    instance_guid: service-instance-guid
    only_manager: false
```


## Circuit breaker

Hystrix-style circuit breaker

See godoc for [CircuitBreakerOption](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/cbreaker#CircuitBreakerOption) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/cbreaker"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: cbreaker.CircuitBreakerConfig{
                        CircuitBreaker: &cbreaker.CircuitBreakerOptions{
                                Enabled: true,
                                Expression: "NetworkErrorRatio() < 0.5",
                                FallbackUrl: "http://my.fallback.com",
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(cbreaker.NewCircuitBreaker()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  circuit_breaker:
    enabled: true
    expression: NetworkErrorRatio() < 0.5
    fallback_url: http://my.fallback.com
```

### Credits

- https://github.com/vulcand/oxy

## Conn limit

Limit number of simultaneous connection

See godoc for [ConnLimitOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/connlimit#ConnLimitOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/connlimit"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: connlimit.ConnLimitConfig{
                        ConnLimit: &connlimit.ConnLimitOptions{
                                Enabled: true,
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(connlimit.NewConnLimit()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  conn_limit:
    enabled: true
```

### Credits

- https://github.com/vulcand/oxy

## Cors

Add cors headers to response

See godoc for [CorsOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/cors#CorsOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/cors"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: cors.CorsConfig{
                        Cors: &cors.CorsOptions{
                                Enabled: true,
                                AllowedOrigins: []string{"http://localhost"},
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(cors.NewCors()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  cors:
    enabled: true
    max_age: 12
    allowed_origins:
    - http://localhost
```

### Credits

- https://github.com/rs/cors

## Infopage

Add an endpoint on upstream to see information like headers set by gobis and user informations set by middlewares (Useful for frontend)

See godoc for [CorsOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/infopage#InfoPageOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/infopage"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: infopage.InfoPageConfig{
                        Cors: &infopage.InfoPageOptions{
                                Enabled: true,
                                Path: "/user_info",
                                ShowAuthorizationHeader: true,
                                AuthorizationKeyName: "token",
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(infopage.NewInfoPage()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  info_page:
    enabled: true
    path: /user_info
    show_authorization_header: true
    authorization_key_name: token
```

Example of json when going to the endpoint `/user_info` when using infopage with oauth2 middleware:

```json
{
	"forward": "true",
	"token": "bearer atokencontent",
	"username": "ausername",
	"groups": ["group1", "group2"]
}
```

## Jwt

Verify a JWT token with its secret/pubkey and can give scopes as groups through [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups) to use it in others middlewares

See godoc for [JwtOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/jwt#JwtOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/jwt"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: jwt.JwtConfig{
                        Ldap: &jwt.JwtOptions{
                                Enabled: true,
                                Alg: "RS256", // this is mandatory due to security issue: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries
                                Secret: "hmac secret or ECDSA/RSA public key", 
                                Issuer: "https://issuer.which.sign.token.com",
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(jwt.NewJwt()))
// create your server
```

### Credits

- https://github.com/auth0/go-jwt-middleware
- https://github.com/dgrijalva/jwt-go

### Use in config file

```yaml
middleware_params:
  jwt:
    enabled: true
    alg: RS256
    secret: hmac secret or ECDSA/RSA public key
    issuer: https://issuer.which.sign.token.com
```

### Tips

- If key `scope.*` is found in the jwt token, thoses scopes will be loaded as groups and others middlewares will
 be able to find groups for the current user by using [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups)

## Ldap

Add basic authentiation based on ldap to upstream

See godoc for [LdapOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/ldap#LdapOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/ldap"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: ldap.LdapConfig{
                        Ldap: &ldap.LdapOptions{
                                Enabled: true,
                                BindDn: "uid=readonly,dc=com",
                                BindPassword: "password",
                                Address: "ldap.example.com:636",
                                InsecureSkipVerify: true,
                                UseSsl: true,
                                SearchBaseDns: "dc=example,dc=com",
                                SearchFilter: "(objectClass=organizationalPerson)&(uid=%s)",
                                GroupSearchBaseDns: "ou=Group,dc=example,dc=com",
                                GroupSearchFilter: "(&(objectClass=posixGroup)(memberUid=%s))",
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(ldap.NewLdap()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  ldap:
    enabled: true
    bind_dn: uid=readonly,dc=com
    bind_password: password
    address: ldap.example.com:636
    insecure_skip_verify: true
    use_ssl: true
    search_base_dns: dc=example,dc=com
    search_filter: (objectClass=organizationalPerson)&(uid=%s)
    group_search_base_dns: ou=Group,dc=example,dc=com
    group_search_filter: (&(objectClass=posixGroup)(memberUid=%s))
```

### Tips

If `GroupSearchBaseDns` and `GroupSearchFilter` params are set the middleware will pass in context 
the list of group accessible by other middlewares by using [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups)

### Credits

- https://github.com/goji/httpauth
- https://github.com/go-ldap/ldap

## Oauth2

Add oauth2 authentication underlying upstream

See godoc for [Oauth2Options](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/oauth2#Oauth2Options) to know more about parameters.

**Note**: If a JWT token is provided by your oauth2 provider you should always use [JWT](#jwt) middleware to verify it.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/oauth2"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: oauth2.Oauth2Config{
                        Ldap: &oauth2.Oauth2Options{
                                Enabled: true,
                                ClientId: "myclientid",
                                ClientSecret: "myclientsecret",
                                AuthorizationUri: "http://github.com/login/oauth/authorize",
                                AccessTokenUri: "http://github.com/login/oauth/access_token",
                                UserInfoUri: "https://api.github.com/user",
                                UseRouteTransport: true,
                                InsecureSkipVerify: false,
                                LoginPath: "/login",
                                LogoutPath: "/logout",
                                AuthKey: "my-super-strong-auth-key",
                                Scopes: []string{},
                                PassToken: false,
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(oauth2.NewOauth2()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  oauth2:
    enabled: true
    client_id: myclientid
    client_secret: myclientsecret
    authorization_uri: http://github.com/login/oauth/authorize
    access_token_uri: https://github.com/login/oauth/access_token
    user_info_uri: https://api.github.com/user
    auth_key: my-super-strong-auth-key
    login_path: /login
    logout_path: /logout
    use_route_transport: true
    insecure_skip_verify: false
    pass_token: false
    scopes: []
```

### Tips

- If user info uri is set username will retrieve from it and be passed through [context username](https://godoc.org/github.com/orange-cloudfoundry/gobis#UserName) to use it in others middlewares
- Scopes will be loaded as groups and others middlewares will
 be able to find groups for the current user by using [context groups](https://godoc.org/github.com/orange-cloudfoundry/gobis#Groups)
- Other middlewares can access to http client with oauth2 context by calling `oauth2.Oauth2Client(req)` where req is `*http.Request` variable

### Credits

- https://github.com/golang/oauth2

## Oauth2request

Retrieve a token with oauth2 client credentials and pass it to upstream

See godoc for [Oauth2RequestOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/oauth2request#Oauth2RequestOptions) to know more about parameters.

**THIS SHOULD BE USED CAREFULLY AS IT CAN BE A SECURITY ISSUE**

### Use programmatically

```go
package main
import "github.com/orange-cloudfoundry/gobis-middlewares/oauth2request"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: oauth2request.Oauth2RequestConfig{
                        Ldap: &oauth2request.Oauth2RequestOptions{
                                Enabled: true,
                                ClientId: "myclientid",
                                ClientSecret: "myclientsecret",
                                AccessTokenUri: "http://github.com/login/oauth/access_token",
                                UseRouteTransport: true,
                                InsecureSkipVerify: false,
                                Scopes: []string{},
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(oauth2request.NewOauth2Request()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  oauth2:
    enabled: true
    client_id: myclientid
    client_secret: myclientsecret
    access_token_uri: https://github.com/login/oauth/access_token
    use_route_transport: true
    insecure_skip_verify: false
    scopes: []
```

### Credits

- https://github.com/golang/oauth2

## Rate limit

Limit number of request in period of time

See godoc for [RateLimitOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/ratelimit#RateLimitOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/ratelimit"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: ratelimit.RateLimitConfig{
                        RateLimit: &ratelimit.RateLimitOptions{
                                Enabled: true,
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(ratelimit.NewRateLimit()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  rate_limit:
    enabled: true
```

### Credits

- https://github.com/vulcand/oxy

## Secure

[Secure](https://github.com/unrolled/secure) is an HTTP middleware for Go that facilitates some quick security wins.

See godoc for [SecureOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/secure#SecureOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/secure"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: secure.SecureConfig{
                        RateLimit: &secure.SecureOptions{
                                Enabled: true,
                                AllowedHosts: []string{"ssl.example.com"},
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(secure.NewSecure()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  secure:
    enabled: true
    allowed_hosts: ["ssl.example.com"]
```

### Credits

- https://github.com/unrolled/secure

## Trace

Structured request and response logger

See godoc for [TraceOptions](https://godoc.org/github.com/orange-cloudfoundry/gobis-middlewares/trace#TraceOptions) to know more about parameters.

### Use programmatically

```go
import "github.com/orange-cloudfoundry/gobis-middlewares/trace"

configHandler := gobis.DefaultHandlerConfig{
        Routes: []gobis.ProxyRoute{
            {
                Name: "myapi",
                Path: "/app/**",
                Url: "http://www.mocky.io/v2/595625d22900008702cd71e8",
                MiddlewareParams: trace.TraceConfig{
                        Trace: &trace.TraceOptions{
                                Enabled: true,
                        },
                },
            },
        },
}
gobisHandler, err := gobis.NewDefaultHandler(configHandler, gobis.NewRouterFactory(trace.NewTrace()))
// create your server
```

### Use in config file

```yaml
middleware_params:
  trace:
    enabled: true
```

### Credits

- https://github.com/vulcand/oxy


