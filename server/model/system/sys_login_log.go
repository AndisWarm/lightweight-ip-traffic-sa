package system

import "time"

// SysLoginLog 用于映射SysLoginLog数据库记录。
// 登录审计日志：记录每次登录成败与来源，可用于追踪暴力破解与异常登录行为。
type SysLoginLog struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	// 尝试登录的用户名
	Username     string    `gorm:"size:64;index;not null" json:"username"`
	// 来源 IP
	IP           string    `gorm:"size:64" json:"ip"`
	// 客户端 UA
	UserAgent    string    `gorm:"size:512" json:"userAgent"`
	// true 成功 / false 失败
	Status       bool      `gorm:"not null" json:"status"`
	// 失败原因
	ErrorMessage string    `gorm:"size:255" json:"errorMessage"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"createdAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysLoginLog) TableName() string {
	return "sys_login_log"
}
