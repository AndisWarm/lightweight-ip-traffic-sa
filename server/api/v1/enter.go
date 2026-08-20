package v1

import (
	"lightweight-ip-traffic-sa/server/api/v1/security"
	"lightweight-ip-traffic-sa/server/api/v1/system"
)

var ApiGroupApp = new(ApiGroup)

// ApiGroup 用于聚合系统域与安全域的接口入口。
type ApiGroup struct {
	SecurityApiGroup security.ApiGroup
	SystemApiGroup   system.ApiGroup
}
