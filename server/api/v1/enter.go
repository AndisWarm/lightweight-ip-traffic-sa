package v1

import (
	"lightweight-ip-traffic-sa/server/api/v1/security"
	"lightweight-ip-traffic-sa/server/api/v1/system"
)

// ApiGroupApp 是控制层的单例入口，router 层通过 v1.ApiGroupApp 拿到各接口的处理函数。
var ApiGroupApp = new(ApiGroup)

// ApiGroup 用于聚合系统域与安全域的接口入口。
type ApiGroup struct {
	SecurityApiGroup security.ApiGroup
	SystemApiGroup   system.ApiGroup
}
