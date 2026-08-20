package security

import (
	"errors"

	"gorm.io/gorm"

	securityModel "lightweight-ip-traffic-sa/server/model/security"
)

// ConfigRepository 用于封装安全态势模块的数据持久化访问。
type ConfigRepository struct{}

// Get 取配置表的第一行（按 id 升序）。sec_security_config 设计为单行运行时配置，
// 因此 Order("id ASC").First 即取到生效配置；无记录时返回 nil，由上层回退到 config.yaml 默认值。
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

// Save 是配置的“新增或整体覆盖”：ID==0 视为首次写入用 Create，否则用 Save 全字段覆盖，
// 保证 sec_security_config 始终只有一条生效记录。
// Save 用于保存配置配置或记录。
func (r *ConfigRepository) Save(db *gorm.DB, config *securityModel.SecurityConfig) error {
	if config.ID == 0 {
		return db.Create(config).Error
	}
	return db.Save(config).Error
}
