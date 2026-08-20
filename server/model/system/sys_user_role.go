package system

import "time"

// SysUserRole 用于映射Sys用户角色数据库记录。
type SysUserRole struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    uint64    `gorm:"index;not null" json:"userId"`
	RoleCode  string    `gorm:"size:32;index;not null" json:"roleCode"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"createdAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysUserRole) TableName() string {
	return "sys_user_role"
}
