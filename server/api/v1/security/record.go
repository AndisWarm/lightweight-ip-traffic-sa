package security

import (
	"net/http"

	"github.com/gin-gonic/gin"

	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/service"
	"lightweight-ip-traffic-sa/server/utils"
)

// RecordApi 用于承接安全态势模块的 HTTP 请求处理。
type RecordApi struct{}

// ListRecords 用于处理检测历史查询接口请求。
func (a *RecordApi) ListRecords(c *gin.Context) {
	// 预置分页默认值并读取过滤字段；前端漏传 page/pageSize 时仍走默认值。
	query := requestModel.RecordListQuery{
		Page:      1,
		PageSize:  10,
		EventType: c.Query("eventType"),
		Keyword:   c.Query("keyword"),
	}
	// ShouldBindQuery 解析 URL 查询串并触发 binding 校验；失败说明入参格式不合法，回 400。
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail("查询参数格式错误"))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.RecordService.ListRecords(query, getRecordClaims(c))
	if err != nil {
		writeServiceError(c, err, "获取历史记录失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// getRecordClaims 用于执行get记录Claims流程。
func getRecordClaims(c *gin.Context) *utils.TokenClaims {
	// 从 JWTAuth 写入上下文的 "claims" 取出登录态，供 service 识别当前操作者。
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	return claims
}
