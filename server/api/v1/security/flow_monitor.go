package security

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/service"
	"lightweight-ip-traffic-sa/server/utils"
)

// FlowMonitorApi 用于承接安全态势模块的 HTTP 请求处理。
type FlowMonitorApi struct{}

// StartSession 用于处理实时流量监控会话启动接口请求。
func (a *FlowMonitorApi) StartSession(c *gin.Context) {
	var req requestModel.StartFlowMonitorSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail("实时流量监控参数格式错误"))
		return
	}
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.StartSession(req, getFlowMonitorClaims(c))
	if err != nil {
		writeServiceError(c, err, "启动实时流量监控失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetCurrentRunningSession 用于处理实时流量监控会话查询接口请求。
func (a *FlowMonitorApi) GetCurrentRunningSession(c *gin.Context) {
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.GetCurrentRunningSession(getFlowMonitorClaims(c))
	if err != nil {
		writeServiceError(c, err, "获取实时流量监控结果失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetSession 用于处理实时流量监控会话查询接口请求。
func (a *FlowMonitorApi) GetSession(c *gin.Context) {
	sessionID := c.Param("id")
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.GetSession(sessionID, getFlowMonitorClaims(c))
	if err != nil {
		writeServiceError(c, err, "获取实时流量监控结果失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// StopSession 用于处理实时流量监控会话停止接口请求。
func (a *FlowMonitorApi) StopSession(c *gin.Context) {
	sessionID := c.Param("id")
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.StopSession(sessionID, getFlowMonitorClaims(c))
	if err != nil {
		writeServiceError(c, err, "停止实时流量监控失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetObserverPanel 用于处理实时流量观察面板查询接口请求。
func (a *FlowMonitorApi) GetObserverPanel(c *gin.Context) {
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.GetObserverPanel(
		c.Query("targetUsername"),
		c.Query("targetRoleCode"),
		getFlowMonitorClaims(c),
	)
	if err != nil {
		writeServiceError(c, err, "获取用户实时流量面板失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetTaskRelationGraph 用于处理任务关联图查询接口请求。
func (a *FlowMonitorApi) GetTaskRelationGraph(c *gin.Context) {
	taskID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || taskID == 0 {
		c.JSON(http.StatusBadRequest, responseModel.Fail("任务 ID 不合法"))
		return
	}
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.GetTaskRelationGraph(taskID)
	if err != nil {
		writeServiceError(c, err, "获取关联图谱失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// getFlowMonitorClaims 用于执行get流量监控Claims流程。
func getFlowMonitorClaims(c *gin.Context) *utils.TokenClaims {
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	return claims
}
