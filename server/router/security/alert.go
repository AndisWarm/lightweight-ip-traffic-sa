package security

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
)

// AlertRouter 用于注册安全态势模块的 HTTP 路由。
type AlertRouter struct{}

// InitAlertRouter 用于注册安全态势接口路由。
func (r *AlertRouter) InitAlertRouter(root *gin.RouterGroup) {
	alertAPI := v1.ApiGroupApp.SecurityApiGroup.AlertApi
	// 在 root（/api/v1）基础上再拼 /alerts 前缀，最终形如 /api/v1/alerts。
	group := root.Group("/alerts")
	{
		// 预警列表/详情是只读查询，对所有已登录角色开放，无需额外角色限制。
		group.GET("", alertAPI.ListAlerts)
		group.GET("/:id", alertAPI.GetAlertDetail)
	}
}
