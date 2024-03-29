package utils

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/vulcand/oxy/utils"
	"net/http"
)

type GobisSourceExtractor struct {
	wrapExtractor utils.SourceExtractor
	variableIsSet bool
}

func NewGobisSourceExtractor(variable string) (utils.SourceExtractor, error) {
	variableIsSet := true
	if variable == "" {
		variable = "client.ip"
		variableIsSet = false
	}
	wrapExtractor, err := utils.NewExtractor(variable)
	if err != nil {
		return nil, err
	}
	return &GobisSourceExtractor{
		wrapExtractor: wrapExtractor,
		variableIsSet: variableIsSet,
	}, nil
}

func (e GobisSourceExtractor) Extract(req *http.Request) (string, int64, error) {
	if e.variableIsSet {
		return e.wrapExtractor.Extract(req)
	}
	user := gobis.Username(req)
	if user == "" {
		return e.wrapExtractor.Extract(req)
	}
	return user, 1, nil
}
