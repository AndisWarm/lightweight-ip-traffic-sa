package initialize

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/middleware"
	"lightweight-ip-traffic-sa/server/router"
)

// SetupRouter 用于装配路由、中间件或运行环境。
func SetupRouter() *gin.Engine {
	engine := gin.Default()
	root := engine.Group("/api/v1")

	routeGroup := router.RouterGroupApp
	routeGroup.System.AuthRouter.InitPublicAuthRouter(root)

	privateRoot := root.Group("")
	privateRoot.Use(middleware.JWTAuth())
	routeGroup.System.AuthRouter.InitPrivateAuthRouter(privateRoot)
	routeGroup.System.AuditRouter.InitAuditRouter(privateRoot)
	routeGroup.Security.TaskRouter.InitTaskRouter(privateRoot)
	routeGroup.Security.DashboardRouter.InitDashboardRouter(privateRoot)
	routeGroup.Security.AlertRouter.InitAlertRouter(privateRoot)
	routeGroup.Security.ConfigRouter.InitConfigRouter(privateRoot)
	routeGroup.Security.RecordRouter.InitRecordRouter(privateRoot)
	routeGroup.Security.FlowMonitorRouter.InitFlowMonitorRouter(privateRoot)

	return engine
}
