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
	group := root.Group("/alerts")
	{
		group.GET("", alertAPI.ListAlerts)
		group.GET("/:id", alertAPI.GetAlertDetail)
	}
}
