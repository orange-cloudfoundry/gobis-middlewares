package utils

import (
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
)

func PathHandler(path string, next http.Handler, handlerFunc func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if gobis.Path(req) != path {
			next.ServeHTTP(w, req)
			return
		}
		handlerFunc(w, req)
	})
}
