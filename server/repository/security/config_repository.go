package security

import (
	"errors"

	"gorm.io/gorm"

	securityModel "lightweight-ip-traffic-sa/server/model/security"
)

// ConfigRepository 用于封装安全态势模块的数据持久化访问。
type ConfigRepository struct{}

// Get 用于访问配置持久化数据。
func (r *ConfigRepository) Get(db *gorm.DB) (*securityModel.SecurityConfig, error) {
	var config securityModel.SecurityConfig
	err := db.Order("id ASC").First(&config).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &config, nil
}

// Save 用于保存配置配置或记录。
func (r *ConfigRepository) Save(db *gorm.DB, config *securityModel.SecurityConfig) error {
	if config.ID == 0 {
		return db.Create(config).Error
	}
	return db.Save(config).Error
}
