package security

import "time"

// AuditLog 用于映射审计Log数据库记录。
type AuditLog struct {
	ID          uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	Category    string    `json:"category" gorm:"column:category;size:32;index"`
	Action      string    `json:"action" gorm:"column:action;size:64;index"`
	Actor       string    `json:"actor" gorm:"column:actor;size:64;index"`
	RoleCode    string    `json:"roleCode" gorm:"column:role_code;size:32;index"`
	TargetType  string    `json:"targetType" gorm:"column:target_type;size:64;index"`
	TargetID    string    `json:"targetId" gorm:"column:target_id;size:128;index"`
	TargetLabel string    `json:"targetLabel" gorm:"column:target_label;size:255"`
	Status      string    `json:"status" gorm:"column:status;size:32;index"`
	Summary     string    `json:"summary" gorm:"column:summary;size:500"`
	Detail      string    `json:"detail" gorm:"column:detail;type:json"`
	IP          string    `json:"ip" gorm:"column:ip;size:64"`
	UserAgent   string    `json:"userAgent" gorm:"column:user_agent;size:512"`
	CreatedAt   time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (AuditLog) TableName() string {
	return "sec_audit_log"
}
