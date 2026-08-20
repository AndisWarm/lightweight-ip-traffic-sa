package system

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
	"lightweight-ip-traffic-sa/server/middleware"
)

// AuthRouter 用于注册系统管理模块的 HTTP 路由。
type AuthRouter struct{}

// InitPublicAuthRouter 用于注册公开鉴权接口路由。
func (r *AuthRouter) InitPublicAuthRouter(root *gin.RouterGroup) {
	authAPI := v1.ApiGroupApp.SystemApiGroup.AuthApi
	// 在 root（/api/v1）基础上再拼 /system 前缀，最终登录 URL 为 /api/v1/system/login。
	group := root.Group("/system")
	{
		// 登录是唯一的公开接口：此刻用户还没有 token，所以不能挂 JWTAuth，否则永远无法登录。
		group.POST("/login", authAPI.Login)
	}
}

// InitPrivateAuthRouter 用于注册登录后用户管理接口路由。
func (r *AuthRouter) InitPrivateAuthRouter(root *gin.RouterGroup) {
	authAPI := v1.ApiGroupApp.SystemApiGroup.AuthApi
	group := root.Group("/system")
	{
		// 这组路由挂在 privateRoot 下，上游已统一挂 JWTAuth，无需每个接口重复声明登录校验。
		group.POST("/logout", authAPI.Logout)
		group.GET("/user/info", authAPI.GetCurrentUser)
		// 用户管理属系统域敏感操作，仅 ADMIN 可访问；MANAGER/USER 命中 RequireRoles 后回 403。
		group.GET("/users", middleware.RequireRoles("ADMIN"), authAPI.ListUsers)
		group.POST("/users", middleware.RequireRoles("ADMIN"), authAPI.CreateUser)
		group.PATCH("/users/:id/status", middleware.RequireRoles("ADMIN"), authAPI.UpdateUserStatus)
		group.PATCH("/users/:id/password", middleware.RequireRoles("ADMIN"), authAPI.ResetPassword)
	}
}
