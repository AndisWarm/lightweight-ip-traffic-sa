package security

import "time"

// IPTask 对应 sec_ip_task 表，是安全检测任务的主表，记录一次 IP/域名检测的完整生命周期。
// task_no 全局唯一，target_ip/status/created_at 建索引以支撑按 IP、状态、时间的列表查询。
// IPTask 用于映射IP任务数据库记录。
type IPTask struct {
	ID           uint64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TaskNo       string     `json:"taskNo" gorm:"column:task_no;size:64;uniqueIndex"`
	InputType    string     `json:"inputType" gorm:"column:input_type;size:16;index"`
	InputValue   string     `json:"inputValue" gorm:"column:input_value;size:255"`
	TargetIP     string     `json:"targetIp" gorm:"column:target_ip;size:64;index"`
	CreatedBy    string     `json:"createdBy" gorm:"column:created_by;size:64;index"`
	TaskStatus   string     `json:"taskStatus" gorm:"column:task_status;size:32;index"`
	ErrorMessage string     `json:"errorMessage" gorm:"column:error_message;size:500"`
	StartedAt    *time.Time `json:"startedAt" gorm:"column:started_at"`
	FinishedAt   *time.Time `json:"finishedAt" gorm:"column:finished_at"`
	CreatedAt    time.Time  `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time  `json:"updatedAt" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (IPTask) TableName() string {
	return "sec_ip_task"
}
