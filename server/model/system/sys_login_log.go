package system

import "time"

// SysLoginLog 用于映射SysLoginLog数据库记录。
type SysLoginLog struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Username     string    `gorm:"size:64;index;not null" json:"username"`
	IP           string    `gorm:"size:64" json:"ip"`
	UserAgent    string    `gorm:"size:512" json:"userAgent"`
	Status       bool      `gorm:"not null" json:"status"`
	ErrorMessage string    `gorm:"size:255" json:"errorMessage"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"createdAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysLoginLog) TableName() string {
	return "sys_login_log"
}
