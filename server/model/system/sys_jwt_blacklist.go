package system

import "time"

// SysJWTBlacklist 用于映射SysJWTBlacklist数据库记录。
type SysJWTBlacklist struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Token     string    `gorm:"size:1024;not null" json:"token"`
	TokenHash string    `gorm:"size:64;uniqueIndex;not null" json:"tokenHash"`
	Username  string    `gorm:"size:64;index;not null" json:"username"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"createdAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysJWTBlacklist) TableName() string {
	return "sys_jwt_blacklist"
}
