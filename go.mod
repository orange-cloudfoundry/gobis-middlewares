module github.com/orange-cloudfoundry/gobis-middlewares

go 1.16

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a

require (
	github.com/ArthurHlt/logrus-cef-formatter v1.0.0
	github.com/HdrHistogram/hdrhistogram-go v1.1.0 // indirect
	github.com/auth0/go-jwt-middleware v1.0.0
	github.com/casbin/casbin v1.9.1
	github.com/codahale/hdrhistogram v1.1.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/form3tech-oss/jwt-go v3.2.2+incompatible
	github.com/goji/httpauth v0.0.0-20160601135302-2da839ab0f4d
	github.com/golang/protobuf v1.5.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/sessions v1.2.1
	github.com/gravitational/trace v1.1.14 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/orange-cloudfoundry/go-auth-pubtkt v1.0.1
	github.com/orange-cloudfoundry/gobis v1.4.2
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.8.1
	github.com/thoas/go-funk v0.8.0 // indirect
	github.com/unrolled/secure v1.0.8
	github.com/vulcand/oxy v1.2.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210324205630-d1beb07c2056 // indirect
	golang.org/x/oauth2 v0.0.0-20210323180902-22b0adad7558
	golang.org/x/term v0.0.0-20210317153231-de623e64d2a6 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
)

retract (
     // mess with jwt libraries
     v1.3.1
)
