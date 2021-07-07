module github.com/orange-cloudfoundry/gobis-middlewares

go 1.16

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a

require (
	github.com/ArthurHlt/logrus-cef-formatter v1.0.0
	github.com/HdrHistogram/hdrhistogram-go v1.1.0 // indirect
	github.com/auth0/go-jwt-middleware v1.0.1
	github.com/casbin/casbin v1.9.1
	github.com/codahale/hdrhistogram v1.1.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/form3tech-oss/jwt-go v3.2.3+incompatible
	github.com/goji/httpauth v0.0.0-20160601135302-2da839ab0f4d
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/sessions v1.2.1
	github.com/gravitational/trace v1.1.15 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/orange-cloudfoundry/go-auth-pubtkt v1.0.1
	github.com/orange-cloudfoundry/gobis v1.4.2
	github.com/rs/cors v1.8.0
	github.com/sirupsen/logrus v1.8.1
	github.com/thoas/go-funk v0.9.0 // indirect
	github.com/unrolled/secure v1.0.9
	github.com/vulcand/oxy v1.3.0
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
)

// mess with jwt libraries
retract v1.3.1
