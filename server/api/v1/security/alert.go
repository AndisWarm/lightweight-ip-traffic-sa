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
	// 先预置分页默认值，再显式读取过滤字段；前端漏传 page/pageSize 时仍走默认值，避免零值导致分页异常。
	query := requestModel.AlertListQuery{
		Page:       1,
		PageSize:   10,
		TargetIP:   c.Query("targetIp"),
		AlertLevel: c.Query("alertLevel"),
		SendStatus: c.Query("sendStatus"),
		Channel:    c.Query("channel"),
	}
	// ShouldBindQuery 把 URL 查询串解析进结构体并触发 binding 标签校验；
	// 失败说明入参格式/类型不合法，属客户端错误，直接回 400。
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
	// :id 是路径参数（字符串），须手动转成 uint64；解析失败或为 0 都视为非法 ID，回 400。
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
	// "claims" 是 JWTAuth 中间件通过 c.Set 写入上下文的登录态；
	// 这里做类型断言取出，供 service 层识别"当前是谁在操作"。
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	return claims
}
