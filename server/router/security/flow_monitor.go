package security

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
	"lightweight-ip-traffic-sa/server/middleware"
)

// FlowMonitorRouter 用于注册安全态势模块的 HTTP 路由。
type FlowMonitorRouter struct{}

// InitFlowMonitorRouter 用于注册安全态势接口路由。
func (r *FlowMonitorRouter) InitFlowMonitorRouter(root *gin.RouterGroup) {
	flowMonitorAPI := v1.ApiGroupApp.SecurityApiGroup.FlowMonitorApi
	group := root.Group("/flow-monitor")
	{
		group.POST("/sessions", middleware.RequireRoles("ADMIN", "MANAGER", "USER"), flowMonitorAPI.StartSession)
		group.GET("/sessions/current", middleware.RequireRoles("ADMIN", "MANAGER", "USER"), flowMonitorAPI.GetCurrentRunningSession)
		group.GET("/sessions/:id", flowMonitorAPI.GetSession)
		group.POST("/sessions/:id/stop", middleware.RequireRoles("ADMIN", "MANAGER", "USER"), flowMonitorAPI.StopSession)
		group.GET("/observer-panel", middleware.RequireRoles("ADMIN", "MANAGER"), flowMonitorAPI.GetObserverPanel)
		group.GET("/tasks/:id/relation-graph", flowMonitorAPI.GetTaskRelationGraph)
	}
}
