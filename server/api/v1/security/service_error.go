package security

import (
	"net/http"

	"github.com/gin-gonic/gin"

	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	securityService "lightweight-ip-traffic-sa/server/service/security"
)

// writeServiceError 用于执行writeServiceError流程。
func writeServiceError(c *gin.Context, err error, fallback string) {
	statusCode := http.StatusInternalServerError

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

	c.JSON(statusCode, responseModel.Fail(securityService.ResolveServiceErrorMessage(err, fallback)))
}
