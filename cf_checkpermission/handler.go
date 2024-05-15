package cf_checkpermission

import (
	"encoding/json"
	"fmt"
	"github.com/orange-cloudfoundry/gobis-middlewares/oauth2"
	"io"
	"net/http"
)

type CfCheckPermissionHandler struct {
	options *CfCheckPermissionOptions
	next    http.Handler
}

type CfPermissionResp struct {
	Manage bool `json:"manage"`
	Read   bool `json:"read"`
}

func NewCfCheckPermissionHandler(options *CfCheckPermissionOptions, next http.Handler) *CfCheckPermissionHandler {
	return &CfCheckPermissionHandler{
		options: options,
		next:    next,
	}
}

func (h CfCheckPermissionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	oauth2Client := oauth2.Oauth2Client(req)
	if oauth2Client == nil {
		panic("orange-cloudfoundry/gobis/middlewares: When enabling cf check permission, you must use oauth2 middleware with cloud_controller_service_permissions.read scope")
	}
	resp, err := oauth2Client.Get(fmt.Sprintf(
		"%s/v2/service_instances/%s/permissions",
		h.options.ApiEndpoint,
		h.options.InstanceGUID),
	)
	if err != nil {
		panic(fmt.Sprintf("orange-cloudfoundry/gobis/middlewares: error when requesting cf check permission: %s", err.Error()))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("orange-cloudfoundry/gobis/middlewares: error when requesting cf check permission: %s", string(b)))
	}
	var permResp CfPermissionResp
	err = json.Unmarshal(b, &permResp)
	if err != nil {
		panic(fmt.Sprintf("orange-cloudfoundry/gobis/middlewares: error when when unmarshaling json response when cf checking permission: %s", err.Error()))
	}

	if h.options.OnlyManager && !permResp.Manage {
		http.Error(w, http.StatusText(401)+": not a manager of this service", 401)
		return
	}
	if !permResp.Read {
		http.Error(w, http.StatusText(401)+": you're not allowed to access to this service", 401)
		return
	}

	h.next.ServeHTTP(w, req)
}
