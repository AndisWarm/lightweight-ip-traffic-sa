package system

import "time"

// SysJWTBlacklist 用于映射SysJWTBlacklist数据库记录。
// JWT 黑名单：登出/踢人时写入，JWTAuth 中间件在鉴权时查这里，命中即拒绝请求（主动失效）。
type SysJWTBlacklist struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	// 原始 token，便于审计回溯
	Token     string    `gorm:"size:1024;not null" json:"token"`
	// token 的 SHA-256 哈希，唯一索引保证 O(1) 去重查询
	TokenHash string    `gorm:"size:64;uniqueIndex;not null" json:"tokenHash"`
	// 归属用户，便于按用户清理
	Username  string    `gorm:"size:64;index;not null" json:"username"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"createdAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SysJWTBlacklist) TableName() string {
	return "sys_jwt_blacklist"
}
