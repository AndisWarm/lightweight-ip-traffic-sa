package system

import (
	"crypto/sha256"
	"encoding/hex"

	"lightweight-ip-traffic-sa/server/global"
	modelSystem "lightweight-ip-traffic-sa/server/model/system"
)

// AuthRepository 用于封装系统管理模块的数据持久化访问。
type AuthRepository struct{}

// buildTokenHash 用于构建TokenHash。
func buildTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

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

// AddTokenToBlacklist 用于访问鉴权持久化数据。
func (r *AuthRepository) AddTokenToBlacklist(token string, username string) error {
	return global.DB.Create(&modelSystem.SysJWTBlacklist{
		Token:     token,
		TokenHash: buildTokenHash(token),
		Username:  username,
	}).Error
}

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
