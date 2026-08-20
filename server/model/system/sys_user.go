package system

import "time"

// SysUser 用于映射Sys用户数据库记录。
// 账号实体：登录凭据 + 角色归属。密码只存哈希，角色编码冗余在用户表便于鉴权时免联表。
type SysUser struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	// 登录名，唯一
	Username     string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	// bcrypt 哈希；json:"-" 防止序列化泄露
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	// 展示名
	DisplayName  string    `gorm:"size:128;not null" json:"displayName"`
	// 角色编码，索引加速按角色查询
	RoleCode     string    `gorm:"size:32;index;not null" json:"roleCode"`
	// 启用/禁用开关
	Enable       bool      `gorm:"not null;default:true" json:"enable"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"createdAt"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updatedAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysUser) TableName() string {
	return "sys_user"
}
