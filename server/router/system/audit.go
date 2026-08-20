package system

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
	"lightweight-ip-traffic-sa/server/middleware"
)

// AuditRouter 用于注册系统管理模块的 HTTP 路由。
type AuditRouter struct{}

// InitAuditRouter 用于注册审计日志接口路由。
func (r *AuditRouter) InitAuditRouter(root *gin.RouterGroup) {
	auditAPI := v1.ApiGroupApp.SystemApiGroup.AuditApi
	group := root.Group("/system")
	{
		// 审计日志记录了登录等安全事件，属敏感信息，仅 ADMIN 可查。
		group.GET("/audit-logs", middleware.RequireRoles("ADMIN"), auditAPI.ListAuditLogs)
	}
}
