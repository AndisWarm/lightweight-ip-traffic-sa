package security

import (
	"net/http"

	"github.com/gin-gonic/gin"

	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/service"
)

// DashboardApi 用于承接安全态势模块的 HTTP 请求处理。
type DashboardApi struct{}

// GetSummary 用于处理态势总览摘要查询接口请求。
func (a *DashboardApi) GetSummary(c *gin.Context) {
	// 总览是跨表聚合的只读结果，无入参；错误交给 writeServiceError 统一映射 HTTP 状态码。
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.DashboardService.GetSummary()
	if err != nil {
		writeServiceError(c, err, "获取总览数据失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetGeoRisk 用于处理地理风险分布查询接口请求。
func (a *DashboardApi) GetGeoRisk(c *gin.Context) {
	// 地理风险热力图是只读聚合数据，无入参；异常同样走 writeServiceError 统一映射。
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.DashboardService.GetGeoRisk()
	if err != nil {
		writeServiceError(c, err, "获取风险 IP 热力图失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}
