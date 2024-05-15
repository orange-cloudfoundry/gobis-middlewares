module github.com/orange-cloudfoundry/gobis-middlewares

go 1.22.3

require (
	github.com/ArthurHlt/logrus-cef-formatter v1.0.0
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/auth0/go-jwt-middleware v1.0.1
	github.com/casbin/casbin v1.9.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible
	github.com/goji/httpauth v0.0.0-20160601135302-2da839ab0f4d
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/gorilla/sessions v1.2.2
	github.com/gravitational/trace v1.4.0 // indirect
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.33.1
	github.com/orange-cloudfoundry/go-auth-pubtkt v1.12.1
	github.com/orange-cloudfoundry/gobis v1.34.0
	github.com/rs/cors v1.11.0
	github.com/sirupsen/logrus v1.9.3
	github.com/unrolled/secure v1.14.0
	github.com/vulcand/oxy v1.4.2
	golang.org/x/crypto v0.23.0
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/oauth2 v0.20.0
	golang.org/x/sys v0.20.0 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
)

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/mailgun/multibuf v0.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/thoas/go-funk v0.9.3 // indirect
	github.com/vulcand/predicate v1.2.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// mess with jwt libraries
retract v1.3.1
