package security

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
)

// DashboardRouter 用于注册安全态势模块的 HTTP 路由。
type DashboardRouter struct{}

// InitDashboardRouter 用于注册安全态势接口路由。
func (r *DashboardRouter) InitDashboardRouter(root *gin.RouterGroup) {
	dashboardAPI := v1.ApiGroupApp.SecurityApiGroup.DashboardApi
	group := root.Group("/dashboard")
	{
		// 总览与地理风险热力图是只读聚合数据，已登录即可查看。
		group.GET("/summary", dashboardAPI.GetSummary)
		group.GET("/geo-risk", dashboardAPI.GetGeoRisk)
	}
}
