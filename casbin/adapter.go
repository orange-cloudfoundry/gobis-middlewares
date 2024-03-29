package casbin

import (
	"errors"
	"github.com/casbin/casbin/model"
	"github.com/orange-cloudfoundry/gobis"
	"net/http"
)

type GobisAdapter struct {
	policies []CasbinPolicy
}

func NewGobisAdapter() *GobisAdapter {
	return &GobisAdapter{policies: make([]CasbinPolicy, 0)}
}

func (a *GobisAdapter) LoadPolicy(model model.Model) error {
	for _, policy := range a.policies {
		err := a.loadPolicy(policy, model)
		if err != nil {
			return err
		}
	}
	return nil
}
func (a *GobisAdapter) loadPolicy(policy CasbinPolicy, model model.Model) error {
	tokens := []string{policy.Sub, policy.Obj}
	if policy.Act != "" {
		tokens = append(tokens, policy.Act)
	}
	key := policy.Type
	sec := key[:1]
	model[sec][key].Policy = append(
		model[sec][key].Policy,
		tokens,
	)
	return nil
}
func (a GobisAdapter) SavePolicy(model model.Model) error {
	return nil
}
func (a *GobisAdapter) AddPolicies(policies ...CasbinPolicy) {
	a.policies = append(a.policies, policies...)
}
func (a *GobisAdapter) AddPoliciesFromRequest(req *http.Request) {
	user := gobis.Username(req)
	groups := gobis.Groups(req)
	for _, group := range groups {
		a.AddPolicies(CasbinPolicy{
			Type: "g",
			Sub:  user,
			Obj:  group,
		})
	}
	var ctxPolicies *[]CasbinPolicy
	gobis.InjectContextValue(req, PolicyContextKey, &ctxPolicies)
	if ctxPolicies == nil {
		return
	}
	for _, ctxPolicy := range *ctxPolicies {
		a.AddPolicies(ctxPolicy)
	}
}
func (a *GobisAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return errors.New("not implemented")
}

// RemovePolicy removes a policy rule from the storage.
func (a *GobisAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return errors.New("not implemented")
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *GobisAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
