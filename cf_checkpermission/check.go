package cf_checkpermission

import (
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/utils"
	"net/http"
)

type CfCheckPermissionConfig struct {
	CfCheckPermission *CfCheckPermissionOptions `mapstructure:"cf_checkpermission" json:"cf_checkpermission" yaml:"cf_checkpermission"`
}

type CfCheckPermissionOptions struct {
	// enable cloud foundry check permission instance
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	// cf api endpoint to call to do the check
	ApiEndpoint string `mapstructure:"api_endpoint" json:"api_endpoint" yaml:"api_endpoint"`
	// Service instance guid to check if user has permission on it
	InstanceGUID string `mapstructure:"instance_guid" json:"instance_guid" yaml:"instance_guid"`
	// Set to true to only permit user which has a manage permission (and not only read permission)
	OnlyManager bool `mapstructure:"only_manager" json:"only_manager" yaml:"only_manager"`
}

type CfCheckPermission struct{}

func NewCfCheckPermission() *CfCheckPermission {
	return &CfCheckPermission{}
}

func (CfCheckPermission) Schema() interface{} {
	return CfCheckPermissionConfig{}
}

func (CfCheckPermission) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(CfCheckPermissionConfig)
	options := config.CfCheckPermission
	if options == nil || !options.Enabled {
		return next, nil
	}
	err := utils.RequiredVal(
		options.ApiEndpoint, "api endpoint",
		options.InstanceGUID, "instance guid",
	)
	if err != nil {
		return next, err
	}

	handler := NewCfCheckPermissionHandler(options, next)
	return handler, nil
}
