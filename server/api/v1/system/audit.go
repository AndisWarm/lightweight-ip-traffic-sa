package system

import (
	"net/http"

	"github.com/gin-gonic/gin"

	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseSecurity "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/service"
)

// AuditApi 用于承接系统管理模块的 HTTP 请求处理。
type AuditApi struct{}

// ListAuditLogs 用于处理List审计Logs接口请求。
func (a *AuditApi) ListAuditLogs(c *gin.Context) {
	// 预置分页默认值；ShouldBindQuery 解析 URL 查询串并触发校验，失败回 400。
	query := requestModel.AuditLogQuery{Page: 1, PageSize: 10}
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail("审计日志查询参数格式错误"))
		return
	}
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.AuditService.ListAuditLogs(query)
	if err != nil {
		// 系统域接口直接回 500，未走 security 域 writeServiceError 的错误类别映射。
		c.JSON(http.StatusInternalServerError, responseSecurity.Fail("获取审计日志失败，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(resp))
}
