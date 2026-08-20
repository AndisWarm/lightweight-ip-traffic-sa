package system

import (
	"crypto/sha256"
	"encoding/hex"

	"lightweight-ip-traffic-sa/server/global"
	modelSystem "lightweight-ip-traffic-sa/server/model/system"
)

// AuthRepository 用于封装系统管理模块的数据持久化访问。
type AuthRepository struct{}

// buildTokenHash 对 JWT 原文做 SHA-256 摘要后再入库。黑名单只存哈希不存明文，
// 即使数据库泄露也不会直接泄露可用的 token；校验时对传入 token 同样哈希后比对。
// buildTokenHash 用于构建TokenHash。
func buildTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// FindUserByUsername 按用户名查用户，登录时用；查无此用户时返回 gorm.ErrRecordNotFound，由上层区分“用户不存在”。
// FindUserByUsername 用于查询鉴权记录。
func (r *AuthRepository) FindUserByUsername(username string) (*modelSystem.SysUser, error) {
	var user modelSystem.SysUser
	err := global.DB.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindUserByID 用于查询鉴权记录。
func (r *AuthRepository) FindUserByID(id uint64) (*modelSystem.SysUser, error) {
	var user modelSystem.SysUser
	err := global.DB.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ListUsers 用于查询鉴权列表。
func (r *AuthRepository) ListUsers() ([]modelSystem.SysUser, error) {
	var users []modelSystem.SysUser
	err := global.DB.Order("id asc").Find(&users).Error
	return users, err
}

// CreateUser 用于写入鉴权记录。
func (r *AuthRepository) CreateUser(user *modelSystem.SysUser) error {
	return global.DB.Create(user).Error
}

// UpdateUserStatus 用于更新鉴权记录。
func (r *AuthRepository) UpdateUserStatus(id uint64, enable bool) error {
	return global.DB.Model(&modelSystem.SysUser{}).Where("id = ?", id).Update("enable", enable).Error
}

// UpdatePassword 用于更新鉴权记录。
func (r *AuthRepository) UpdatePassword(id uint64, passwordHash string) error {
	return global.DB.Model(&modelSystem.SysUser{}).Where("id = ?", id).Update("password_hash", passwordHash).Error
}

// AddTokenToBlacklist 登出时把 token 写入黑名单，配合 JWTAuth 中间件的哈希比对实现“主动失效”。
// AddTokenToBlacklist 用于访问鉴权持久化数据。
func (r *AuthRepository) AddTokenToBlacklist(token string, username string) error {
	return global.DB.Create(&modelSystem.SysJWTBlacklist{
		Token:     token,
		TokenHash: buildTokenHash(token),
		Username:  username,
	}).Error
}

// IsTokenBlacklisted 按 token 哈希查黑名单，命中即拒绝放行，是登出后 token 立即失效的关键判断。
// IsTokenBlacklisted 用于访问鉴权持久化数据。
func (r *AuthRepository) IsTokenBlacklisted(token string) (bool, error) {
	var count int64
	err := global.DB.Model(&modelSystem.SysJWTBlacklist{}).Where("token_hash = ?", buildTokenHash(token)).Count(&count).Error
	return count > 0, err
}

// CreateLoginLog 用于写入鉴权记录。
func (r *AuthRepository) CreateLoginLog(log *modelSystem.SysLoginLog) error {
	return global.DB.Create(log).Error
}
