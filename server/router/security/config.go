package security

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
	"lightweight-ip-traffic-sa/server/middleware"
)

// ConfigRouter 用于注册安全态势模块的 HTTP 路由。
type ConfigRouter struct{}

// InitConfigRouter 用于注册安全态势接口路由。
func (r *ConfigRouter) InitConfigRouter(root *gin.RouterGroup) {
	configAPI := v1.ApiGroupApp.SecurityApiGroup.ConfigApi
	group := root.Group("/configs")
	{
		group.GET("/security", configAPI.GetSecurityConfig)
		group.GET("/security/flow-interfaces", configAPI.ListFlowInterfaces)
		group.PUT("/security", middleware.RequireRoles("ADMIN", "MANAGER"), configAPI.UpdateSecurityConfig)
		group.PATCH("/security/flow-toggle", middleware.RequireRoles("ADMIN", "MANAGER"), configAPI.UpdateFlowToggle)
	}
}
