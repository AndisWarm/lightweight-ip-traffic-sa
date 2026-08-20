package security

import "time"

// AlertRecord 对应 sec_alert_record 表。实时监控产生的预警不绑定任务，因此 TaskID/ScoreID 用指针可为 NULL；
// source_type 区分 TASK / FLOW_MONITOR，send_status 跟踪通知发送状态（PENDING/SENT/FAILED）。
// AlertRecord 用于映射预警记录数据库记录。
type AlertRecord struct {
	ID               uint64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TaskID           *uint64    `json:"taskId" gorm:"column:task_id;index"`
	ScoreID          *uint64    `json:"scoreId" gorm:"column:score_id;index"`
	IP               string     `json:"ip" gorm:"column:ip;size:64;index"`
	SourceType       string     `json:"sourceType" gorm:"column:source_type;size:32;index"`
	SourceLabel      string     `json:"sourceLabel" gorm:"column:source_label;size:128"`
	MonitorSessionID string     `json:"monitorSessionId" gorm:"column:monitor_session_id;size:64;index"`
	AlertLevel       string     `json:"alertLevel" gorm:"column:alert_level;size:32;index"`
	AlertTitle       string     `json:"alertTitle" gorm:"column:alert_title;size:255"`
	AlertContent     string     `json:"alertContent" gorm:"column:alert_content;type:text"`
	Channel          string     `json:"channel" gorm:"column:channel;size:32;index"`
	SendStatus       string     `json:"sendStatus" gorm:"column:send_status;size:32;index"`
	SendTime         *time.Time `json:"sendTime" gorm:"column:send_time"`
	CreatedAt        time.Time  `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (AlertRecord) TableName() string {
	return "sec_alert_record"
}
