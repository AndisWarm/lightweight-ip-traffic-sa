package system

import "time"

// SysUser 用于映射Sys用户数据库记录。
type SysUser struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	DisplayName  string    `gorm:"size:128;not null" json:"displayName"`
	RoleCode     string    `gorm:"size:32;index;not null" json:"roleCode"`
	Enable       bool      `gorm:"not null;default:true" json:"enable"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"createdAt"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updatedAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysUser) TableName() string {
	return "sys_user"
}
