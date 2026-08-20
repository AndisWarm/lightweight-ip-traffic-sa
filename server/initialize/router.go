package initialize

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/middleware"
	"lightweight-ip-traffic-sa/server/router"
)

// SetupRouter 用于装配路由、中间件或运行环境。
func SetupRouter() *gin.Engine {
	// gin.Default() 自带 Logger 与 Recovery 中间件，Recovery 能兜住 handler 里的 panic，避免单个请求拖垮进程。
	engine := gin.Default()
	// 所有业务接口统一挂在 /api/v1 前缀下。
	root := engine.Group("/api/v1")

	routeGroup := router.RouterGroupApp
	// 登录接口是公共路由，无需 token；其余全部挂到带 JWTAuth 中间件的私有分组，
	// 中间件按洋葱模型在进入具体 handler 前先校验 token 与黑名单。
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
