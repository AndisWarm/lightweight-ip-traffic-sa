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
	// ShouldBindJSON 解析请求体；失败说明入参格式不合法，直接回 400。
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
	// 查询"当前登录用户"正在跑的会话，身份从 claims 取，前端无需传参。
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.FlowMonitorService.GetCurrentRunningSession(getFlowMonitorClaims(c))
	if err != nil {
		writeServiceError(c, err, "获取实时流量监控结果失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetSession 用于处理实时流量监控会话查询接口请求。
func (a *FlowMonitorApi) GetSession(c *gin.Context) {
	// 会话 ID 是字符串路径参数（可能为 UUID 等非纯数字），故不转 uint，直接透传给 service。
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
	// 停止指定会话；把 claims 传下去，让 service 校验"只能停自己的会话"。
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
	// 管理员观察面板：通过 targetUsername/targetRoleCode 指定观察对象；实际角色限制已在路由层挂为 ADMIN/MANAGER。
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
	// :id 是路径参数，转成 uint64；失败或为 0 说明 ID 不合法，回 400。
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
	// 从 JWTAuth 写入上下文的 "claims" 取出登录态，供 service 识别当前操作者。
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	return claims
}
