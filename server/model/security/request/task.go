package request

import (
	"errors"
	"strings"
)

// CreateTaskRequest 用于承载Create任务接口的请求参数。
type CreateTaskRequest struct {
	TargetIP    string `json:"targetIp" binding:"required"`
	RequestedBy string `json:"requestedBy"`
}

// ResolvedTaskTarget 用于映射Resolved任务Target数据库记录。
type ResolvedTaskTarget struct {
	InputType  string
	InputValue string
	TargetIP   string
}

// Normalize 用于规范化当前。
func (r *CreateTaskRequest) Normalize() {
	r.TargetIP = strings.TrimSpace(r.TargetIP)
	r.RequestedBy = strings.TrimSpace(r.RequestedBy)
}

// TaskListQuery 用于映射任务ListQuery数据库记录。
type TaskListQuery struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"pageSize"`
	TargetIP   string `form:"targetIp"`
	TaskStatus string `form:"taskStatus"`
	RiskLevel  string `form:"riskLevel"`
	SortBy     string `form:"sortBy"`
	SortOrder  string `form:"sortOrder"`
}

var (
	allowedTaskStatus = map[string]struct{}{
		"PENDING": {},
		"RUNNING": {},
		"SUCCESS": {},
		"FAILED":  {},
	}
	allowedRiskLevel = map[string]struct{}{
		"LOW":      {},
		"MEDIUM":   {},
		"HIGH":     {},
		"CRITICAL": {},
	}
	allowedTaskSortBy = map[string]struct{}{
		"createdAt":  {},
		"scoreValue": {},
		"riskLevel":  {},
	}
	allowedTaskSortOrder = map[string]struct{}{
		"asc":  {},
		"desc": {},
	}
)

// Normalize 用于规范化当前。
func (q *TaskListQuery) Normalize() {
	q.TargetIP = strings.TrimSpace(q.TargetIP)
	q.TaskStatus = strings.ToUpper(strings.TrimSpace(q.TaskStatus))
	q.RiskLevel = strings.ToUpper(strings.TrimSpace(q.RiskLevel))
	q.SortBy = strings.TrimSpace(q.SortBy)
	q.SortOrder = strings.ToLower(strings.TrimSpace(q.SortOrder))

	if q.SortBy == "" {
		q.SortBy = "createdAt"
	}
	if q.SortOrder == "" {
		q.SortOrder = "desc"
	}
}

// Validate 用于校验当前。
func (q TaskListQuery) Validate() error {
	if q.TaskStatus != "" {
		if _, ok := allowedTaskStatus[q.TaskStatus]; !ok {
			return errors.New("任务状态筛选值不合法")
		}
	}
	if q.RiskLevel != "" {
		if _, ok := allowedRiskLevel[q.RiskLevel]; !ok {
			return errors.New("风险等级筛选值不合法")
		}
	}
	if _, ok := allowedTaskSortBy[q.SortBy]; !ok {
		return errors.New("排序字段不支持")
	}
	if _, ok := allowedTaskSortOrder[q.SortOrder]; !ok {
		return errors.New("排序方向不支持")
	}
	return nil
}
