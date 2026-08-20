package security

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/service"
	"lightweight-ip-traffic-sa/server/utils"
)

// TaskApi 用于承接安全态势模块的 HTTP 请求处理。
type TaskApi struct{}

// CreateTask 用于处理安全检测任务创建接口请求。
func (a *TaskApi) CreateTask(c *gin.Context) {
	var req requestModel.CreateTaskRequest
	// ShouldBindJSON 解析 body 并触发 binding 标签校验。错误分两类：
	// 一是 validator.ValidationErrors（字段校验失败，如 targetIp 为空），给出更精确的提示；
	// 二是 JSON 本身非法（类型错、语法错），只能笼统回"格式错误"。
	if err := c.ShouldBindJSON(&req); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			c.JSON(http.StatusBadRequest, responseModel.Fail("目标 IP 不能为空"))
			return
		}
		c.JSON(http.StatusBadRequest, responseModel.Fail("请求参数格式错误"))
		return
	}
	// Normalize 做字段规整（如去空格、转小写）；再兜底校验一次 TargetIP，防止绕过 binding 的空值。
	req.Normalize()
	if req.TargetIP == "" {
		c.JSON(http.StatusBadRequest, responseModel.Fail("目标 IP 不能为空"))
		return
	}

	// 从上下文取出当前登录用户名作为 actor，供 service 记录"谁创建了这个任务"（审计归属）。
	actor := ""
	if value, ok := c.Get("claims"); ok {
		if claims, ok := value.(*utils.TokenClaims); ok {
			actor = claims.Username
		}
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.TaskService.CreateTaskWithActor(req, actor)
	if err != nil {
		writeServiceError(c, err, "创建检测任务失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// GetTaskDetail 用于处理安全检测任务详情查询接口请求。
func (a *TaskApi) GetTaskDetail(c *gin.Context) {
	// 路径参数 :id 是字符串，转成 uint64；失败或为 0 说明 ID 不合法，回 400。
	taskID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || taskID == 0 {
		c.JSON(http.StatusBadRequest, responseModel.Fail("任务 ID 不合法"))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.TaskService.GetTaskDetail(taskID)
	if err != nil {
		writeServiceError(c, err, "获取任务详情失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}

// DeleteTask 用于处理安全检测任务删除接口请求。
func (a *TaskApi) DeleteTask(c *gin.Context) {
	// 删除前先解析并校验 :id；失败或为 0 直接回 400，避免误删。
	taskID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || taskID == 0 {
		c.JSON(http.StatusBadRequest, responseModel.Fail("任务 ID 不合法"))
		return
	}

	if err := service.ServiceGroupApp.SecurityServiceGroup.TaskService.DeleteTask(taskID); err != nil {
		writeServiceError(c, err, "删除检测任务失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(gin.H{"deleted": true, "taskId": taskID}))
}

// ListTasks 用于处理安全检测任务列表查询接口请求。
func (a *TaskApi) ListTasks(c *gin.Context) {
	// 预置分页与排序默认值（按创建时间倒序），前端可选择性覆盖。
	query := requestModel.TaskListQuery{
		Page:       1,
		PageSize:   10,
		SortBy:     "createdAt",
		SortOrder:  "desc",
		TargetIP:   c.Query("targetIp"),
		TaskStatus: c.Query("taskStatus"),
		RiskLevel:  c.Query("riskLevel"),
	}
	// 绑定 URL 查询串并触发 binding 校验；失败回 400。
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail("查询参数格式错误"))
		return
	}
	// 绑定后做规整与自定义校验（如排序字段/方向的合法性），不合法直接回 400。
	query.Normalize()
	if err := query.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, responseModel.Fail(err.Error()))
		return
	}

	resp, err := service.ServiceGroupApp.SecurityServiceGroup.TaskService.ListTasks(query)
	if err != nil {
		writeServiceError(c, err, "获取任务列表失败，请稍后重试")
		return
	}
	c.JSON(http.StatusOK, responseModel.Ok(resp))
}
