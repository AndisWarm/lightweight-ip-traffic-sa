package security

import (
	"github.com/gin-gonic/gin"

	"lightweight-ip-traffic-sa/server/api/v1"
)

// RecordRouter 用于注册安全态势模块的 HTTP 路由。
type RecordRouter struct{}

// InitRecordRouter 用于注册安全态势接口路由。
func (r *RecordRouter) InitRecordRouter(root *gin.RouterGroup) {
	recordAPI := v1.ApiGroupApp.SecurityApiGroup.RecordApi
	group := root.Group("/records")
	{
		// 检测历史记录是只读查询，已登录即可查看。
		group.GET("", recordAPI.ListRecords)
	}
}
