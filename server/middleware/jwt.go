package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	responseSecurity "lightweight-ip-traffic-sa/server/model/security/response"
	serviceSystem "lightweight-ip-traffic-sa/server/service/system"
	"lightweight-ip-traffic-sa/server/utils"
)

// JWTAuth 用于执行JWT鉴权流程。
func JWTAuth() gin.HandlerFunc {
	authService := serviceSystem.NewAuthService()
	return func(c *gin.Context) {
		token := utils.ExtractToken(c)
		claims, err := utils.ParseToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
			c.Abort()
			return
		}
		blacklisted, err := authService.IsTokenBlacklisted(token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, responseSecurity.Fail("令牌校验失败"))
			c.Abort()
			return
		}
		if blacklisted {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("登录状态已失效"))
			c.Abort()
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

// RequireRoles 用于执行RequireRoles流程。
func RequireRoles(roleCodes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get("claims")
		if !ok {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
			c.Abort()
			return
		}
		claims, ok := value.(*utils.TokenClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("登录信息无效"))
			c.Abort()
			return
		}
		for _, roleCode := range roleCodes {
			if claims.RoleCode == roleCode {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, responseSecurity.Fail("无权访问当前资源"))
		c.Abort()
	}
}
