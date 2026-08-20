package security

import (
	"net/http"

	"github.com/gin-gonic/gin"

	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	securityService "lightweight-ip-traffic-sa/server/service/security"
)

// writeServiceError 用于执行writeServiceError流程。
func writeServiceError(c *gin.Context, err error, fallback string) {
	// 默认按 500 处理：service 返回的未分类错误（含 Internal）一律视为服务端内部错误，不向客户端泄露细节。
	statusCode := http.StatusInternalServerError

	// 把 service 层的业务错误类别翻译成对应的 HTTP 状态码。
	// 这是 api 层"HTTP 世界 ↔ 业务世界"翻译职责的核心，避免在 controller 里散落大量 if err 判断。
	switch securityService.ResolveServiceErrorCategory(err) {
	case securityService.ServiceErrorCategoryInvalidArgument:
		statusCode = http.StatusBadRequest
	case securityService.ServiceErrorCategoryUnauthenticated:
		statusCode = http.StatusUnauthorized
	case securityService.ServiceErrorCategoryPermissionDenied:
		statusCode = http.StatusForbidden
	case securityService.ServiceErrorCategoryConflict:
		statusCode = http.StatusConflict
	case securityService.ServiceErrorCategoryNotFound:
		statusCode = http.StatusNotFound
	case securityService.ServiceErrorCategoryExternalDependency:
		statusCode = http.StatusServiceUnavailable
	}

	// 统一用 response.Fail 输出 {code, message, data} 结构；message 优先取业务错误文案，取不到再用兜底文案。
	c.JSON(statusCode, responseModel.Fail(securityService.ResolveServiceErrorMessage(err, fallback)))
}
