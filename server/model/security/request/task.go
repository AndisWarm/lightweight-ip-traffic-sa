package request

import (
	"errors"
	"strings"
)

// CreateTaskRequest 是创建检测任务接口的入参。TargetIP 必填（实际可传 IP 或域名，
// 由 service 层解析成目标 IP）；RequestedBy 由前端透传的发起人标识，可为空。
// CreateTaskRequest 用于承载Create任务接口的请求参数。
type CreateTaskRequest struct {
	TargetIP    string `json:"targetIp" binding:"required"`
	RequestedBy string `json:"requestedBy"`
}

// ResolvedTaskTarget 是 CreateTaskRequest 解析后的规范化目标：区分原始输入类型（IP/DOMAIN）、
// 原始值与最终用于检测的目标 IP。
// ResolvedTaskTarget 用于映射Resolved任务Target数据库记录。
type ResolvedTaskTarget struct {
	InputType  string
	InputValue string
	TargetIP   string
}

// Normalize 去除入参首尾空白，避免前端多传空格导致后续校验/入库出现意外匹配。
// Normalize 用于规范化当前。
func (r *CreateTaskRequest) Normalize() {
	r.TargetIP = strings.TrimSpace(r.TargetIP)
	r.RequestedBy = strings.TrimSpace(r.RequestedBy)
}

// TaskListQuery 是任务列表接口的查询入参。SortBy/SortOrder 等字段会在 Normalize 中归一化、
// 在 Validate 中做白名单校验（防止任意排序字段/方向被拼进 SQL），之后才交给 repository 使用。
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

// Normalize 把筛选/排序参数归一化：状态与风险等级统一大写以匹配库中枚举值，
// 排序字段与方向补默认值，保证 Validate 的比对口径一致。
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

// Validate 对筛选/排序参数做白名单校验：非法的状态/等级/排序字段/方向直接报错，
// 从源头杜绝把未校验字符串拼进 ORDER BY 造成的 SQL 注入风险。
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
