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

// AlertApi 用于承接安全态势模块的 HTTP 请求处理。
type AlertApi struct{}

// ListAlerts 用于处理预警列表查询接口请求。
func (a *AlertApi) ListAlerts(c *gin.Context) {
	query := requestModel.AlertListQuery{
		Page:       1,
		PageSize:   10,
		TargetIP:   c.Query("targetIp"),
		AlertLevel: c.Query("alertLevel"),
		SendStatus: c.Query("sendStatus"),
		Channel:    c.Query("channel"),
	}
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail("查询参数格式错误"))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.AlertService.ListAlerts(query, getAlertClaims(c))
	if err != nil {
		writeServiceError(c, err, "获取预警列表失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetAlertDetail 用于处理预警详情查询接口请求。
func (a *AlertApi) GetAlertDetail(c *gin.Context) {
	alertID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || alertID == 0 {
		c.JSON(http.StatusBadRequest, responseModel.Fail("预警 ID 不合法"))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.AlertService.GetAlertDetail(alertID, getAlertClaims(c))
	if err != nil {
		writeServiceError(c, err, "获取预警详情失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// getAlertClaims 用于执行get预警Claims流程。
func getAlertClaims(c *gin.Context) *utils.TokenClaims {
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	return claims
}
