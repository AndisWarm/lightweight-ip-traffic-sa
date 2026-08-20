package system

import "time"

// SysUserRole 用于映射Sys用户角色数据库记录。
// 用户-角色多对多关联表，为后续"一个用户多角色"的扩展预留；当前实现用户表已冗余 RoleCode。
type SysUserRole struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	// 用户 ID
	UserID    uint64    `gorm:"index;not null" json:"userId"`
	// 角色编码
	RoleCode  string    `gorm:"size:32;index;not null" json:"roleCode"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"createdAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysUserRole) TableName() string {
	return "sys_user_role"
}
