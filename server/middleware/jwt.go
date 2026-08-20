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
		// 先从 Authorization: Bearer xxx 头取出 token，再解析出 Claims。
		// 解析失败通常意味着 token 缺失、过期、被篡改或签名不匹配，一律按未登录处理。
		token := utils.ExtractToken(c)
		claims, err := utils.ParseToken(token)
		if err != nil {
			// 解析失败回 401；c.Abort() 会中断洋葱链，后续 RequireRoles 与 handler 都不会再执行。
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
			c.Abort()
			return
		}
		// 黑名单校验：JWT 本身无状态，签发后过期前一直有效；用户退出时把 token 写进黑名单，
		// 这里通过 SHA256 哈希比对实现"退出即失效"。注意与上面解析失败的区别：
		// 解析失败是"token 不合法"，黑名单命中是"token 合法但已被登出"。
		blacklisted, err := authService.IsTokenBlacklisted(token)
		if err != nil {
			// 查黑名单依赖 DB，失败属于服务端故障，回 500 而不是误判成未登录。
			c.JSON(http.StatusInternalServerError, responseSecurity.Fail("令牌校验失败"))
			c.Abort()
			return
		}
		if blacklisted {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("登录状态已失效"))
			c.Abort()
			return
		}
		// 把解析出的身份写入 gin 上下文，供后续 RequireRoles 中间件和 handler 通过 c.Get("claims") 读取。
		c.Set("claims", claims)
		// Next 放行到下一个中间件/处理函数，形成"请求穿过洋葱"的流转。
		c.Next()
	}
}

// RequireRoles 用于执行RequireRoles流程。
func RequireRoles(roleCodes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 依赖 JWTAuth 已把 claims 写入上下文；取不到说明该路由没挂鉴权或 token 无效。
		value, ok := c.Get("claims")
		if !ok {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
			c.Abort()
			return
		}
		// 类型断言失败说明上下文里不是预期的 TokenClaims，属于异常数据，按未登录处理。
		claims, ok := value.(*utils.TokenClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, responseSecurity.Fail("登录信息无效"))
			c.Abort()
			return
		}
		// 遍历调用方传入的允许角色列表，命中任意一个就放行，实现"白名单"式授权。
		for _, roleCode := range roleCodes {
			if claims.RoleCode == roleCode {
				c.Next()
				return
			}
		}
		// 全部不匹配 => 已登录但权限不足，回 403 而非 401（身份没问题，是权限不够）。
		c.JSON(http.StatusForbidden, responseSecurity.Fail("无权访问当前资源"))
		c.Abort()
	}
}
