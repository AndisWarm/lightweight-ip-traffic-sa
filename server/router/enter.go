package router

import (
	"lightweight-ip-traffic-sa/server/router/security"
	"lightweight-ip-traffic-sa/server/router/system"
)

// RouterGroupApp 是路由注册的单例入口，initialize/router.go 通过它把各域路由挂到 /api/v1 根分组下。
var RouterGroupApp = new(RouterGroup)

// RouterGroup 用于聚合系统域与安全域的路由注册器。
type RouterGroup struct {
	Security security.RouterGroup
	System   system.RouterGroup
}
