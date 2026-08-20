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
	// 在 root（/api/v1）基础上再拼 /tasks 前缀，最终形如 /api/v1/tasks。
	group := root.Group("/tasks")
	{
		// 创建/删除会改变检测资源，只允许 ADMIN/MANAGER；列表与详情为只读，所有已登录角色可访问。
		group.POST("", middleware.RequireRoles("ADMIN", "MANAGER"), taskAPI.CreateTask)
		group.GET("", taskAPI.ListTasks)
		group.GET("/:id", taskAPI.GetTaskDetail)
		group.DELETE("/:id", middleware.RequireRoles("ADMIN", "MANAGER"), taskAPI.DeleteTask)
	}
}
