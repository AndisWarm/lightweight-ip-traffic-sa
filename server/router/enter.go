package router

import (
	"lightweight-ip-traffic-sa/server/router/security"
	"lightweight-ip-traffic-sa/server/router/system"
)

var RouterGroupApp = new(RouterGroup)

// RouterGroup 用于聚合系统域与安全域的路由注册器。
type RouterGroup struct {
	Security security.RouterGroup
	System   system.RouterGroup
}
