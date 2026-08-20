package system

import "time"

// SysRole 用于映射Sys角色数据库记录。
type SysRole struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	RoleCode    string    `gorm:"size:32;uniqueIndex;not null" json:"roleCode"`
	RoleName    string    `gorm:"size:64;not null" json:"roleName"`
	Description string    `gorm:"size:255" json:"description"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"createdAt"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updatedAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysRole) TableName() string {
	return "sys_role"
}
