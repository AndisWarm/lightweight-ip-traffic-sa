package security

import (
	securityModel "lightweight-ip-traffic-sa/server/model/security"

	"gorm.io/gorm"
)

// BaseInfoRepository 用于封装安全态势模块的数据持久化访问。
type BaseInfoRepository struct{}

// BaseInfoPayloadRow 用于承载基础信息载荷数据库查询行。
type BaseInfoPayloadRow struct {
	RawPayload string
}

// Create 用于写入基础信息记录。
func (r *BaseInfoRepository) Create(db *gorm.DB, baseInfo *securityModel.IPBaseInfo) error {
	return db.Create(baseInfo).Error
}

// FindByTaskID 用于查询基础信息记录。
func (r *BaseInfoRepository) FindByTaskID(db *gorm.DB, taskID uint64) (*securityModel.IPBaseInfo, error) {
	var baseInfo securityModel.IPBaseInfo
	err := db.Where("task_id = ?", taskID).First(&baseInfo).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &baseInfo, nil
}

// ListPayloads 只取 raw_payload 列（Geo/RDAP 原始 JSON），用于离线重建画像，避免加载整行多余字段。
// ListPayloads 用于查询基础信息列表。
func (r *BaseInfoRepository) ListPayloads(db *gorm.DB) ([]BaseInfoPayloadRow, error) {
	var rows []BaseInfoPayloadRow
	err := db.Model(&securityModel.IPBaseInfo{}).
		Select("raw_payload").
		Scan(&rows).Error
	return rows, err
}

// DeleteByTaskID 用于删除基础信息记录。
func (r *BaseInfoRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.IPBaseInfo{}).Error
}
