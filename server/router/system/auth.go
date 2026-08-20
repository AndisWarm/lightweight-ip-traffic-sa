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
	group := root.Group("/system")
	{
		group.POST("/login", authAPI.Login)
	}
}

// InitPrivateAuthRouter 用于注册登录后用户管理接口路由。
func (r *AuthRouter) InitPrivateAuthRouter(root *gin.RouterGroup) {
	authAPI := v1.ApiGroupApp.SystemApiGroup.AuthApi
	group := root.Group("/system")
	{
		group.POST("/logout", authAPI.Logout)
		group.GET("/user/info", authAPI.GetCurrentUser)
		group.GET("/users", middleware.RequireRoles("ADMIN"), authAPI.ListUsers)
		group.POST("/users", middleware.RequireRoles("ADMIN"), authAPI.CreateUser)
		group.PATCH("/users/:id/status", middleware.RequireRoles("ADMIN"), authAPI.UpdateUserStatus)
		group.PATCH("/users/:id/password", middleware.RequireRoles("ADMIN"), authAPI.ResetPassword)
	}
}
