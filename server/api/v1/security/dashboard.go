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
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.DashboardService.GetSummary()
	if err != nil {
		writeServiceError(c, err, "获取总览数据失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetGeoRisk 用于处理地理风险分布查询接口请求。
func (a *DashboardApi) GetGeoRisk(c *gin.Context) {
	resp, err := service.ServiceGroupApp.SecurityServiceGroup.DashboardService.GetGeoRisk()
	if err != nil {
		writeServiceError(c, err, "获取风险 IP 热力图失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}
