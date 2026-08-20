package security

import (
	"net/http"

	"github.com/gin-gonic/gin"

	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/service"
)

// ConfigApi 用于承接安全态势模块的 HTTP 请求处理。
type ConfigApi struct{}

// GetSecurityConfig 用于处理安全配置查询接口请求。
func (a *ConfigApi) GetSecurityConfig(c *gin.Context) {
	// GET 查询无请求体，直接调 service；业务错误统一由 writeServiceError 按类别映射成 HTTP 状态码。
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.ConfigService.GetSecurityConfig()
	if err != nil {
		writeServiceError(c, err, "获取安全配置失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// UpdateSecurityConfig 用于处理安全配置更新接口请求。
func (a *ConfigApi) UpdateSecurityConfig(c *gin.Context) {
	// ShouldBindJSON 把 HTTP body 解析为请求结构体，失败说明入参格式/类型不合法，直接回 400。
	var req requestModel.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail("安全配置参数格式错误"))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.ConfigService.UpdateSecurityConfig(req)
	if err != nil {
		writeServiceError(c, err, "更新安全配置失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// UpdateFlowToggle 用于处理流量增强开关更新接口请求。
func (a *ConfigApi) UpdateFlowToggle(c *gin.Context) {
	// Enabled 是 *bool 指针：用 nil 区分"前端没传"和"传了 false"。
	// 解析失败或根本没传该字段都按入参不合法回 400，避免把开关误关掉。
	var req requestModel.UpdateFlowToggleRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail("流量开关参数格式错误"))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.ConfigService.UpdateFlowToggle(req)
	if err != nil {
		writeServiceError(c, err, "更新流量开关失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// ListFlowInterfaces 用于处理在线抓包网卡枚举接口请求。
func (a *ConfigApi) ListFlowInterfaces(c *gin.Context) {
	// 枚举本机网卡属纯查询，无入参；错误同样交给 writeServiceError 统一映射。
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.ConfigService.ListFlowInterfaces()
	if err != nil {
		writeServiceError(c, err, "获取在线抓包网卡列表失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}
