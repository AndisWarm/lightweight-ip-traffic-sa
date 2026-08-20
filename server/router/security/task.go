package security

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
	"lightweight-ip-traffic-sa/server/middleware"
)

// TaskRouter 用于注册安全态势模块的 HTTP 路由。
type TaskRouter struct{}

// InitTaskRouter 用于注册安全态势接口路由。
func (r *TaskRouter) InitTaskRouter(root *gin.RouterGroup) {
	taskAPI := v1.ApiGroupApp.SecurityApiGroup.TaskApi
	group := root.Group("/tasks")
	{
		group.POST("", middleware.RequireRoles("ADMIN", "MANAGER"), taskAPI.CreateTask)
		group.GET("", taskAPI.ListTasks)
		group.GET("/:id", taskAPI.GetTaskDetail)
		group.DELETE("/:id", middleware.RequireRoles("ADMIN", "MANAGER"), taskAPI.DeleteTask)
	}
}
