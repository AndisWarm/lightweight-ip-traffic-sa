package security

import (
	securityModel "lightweight-ip-traffic-sa/server/model/security"

	"gorm.io/gorm"
)

// FeatureRepository 用于封装安全态势模块的数据持久化访问。
type FeatureRepository struct{}

// FeaturePayloadRow 用于承载特征载荷数据库查询行。
type FeaturePayloadRow struct {
	NormalizedFeatures string
}

// AttackSurfaceSummary 用于承载AttackSurface摘要汇总结果。
type AttackSurfaceSummary struct {
	ExposedTaskCount  int64
	HighRiskPortTasks int64
}

// Create 用于写入特征记录。
func (r *FeatureRepository) Create(db *gorm.DB, snapshot *securityModel.FeatureSnapshot) error {
	return db.Create(snapshot).Error
}

// FindByTaskID 用于查询特征记录。
func (r *FeatureRepository) FindByTaskID(db *gorm.DB, taskID uint64) (*securityModel.FeatureSnapshot, error) {
	var snapshot securityModel.FeatureSnapshot
	err := db.Where("task_id = ?", taskID).First(&snapshot).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &snapshot, nil
}

// ListPayloads 用于查询特征列表。
func (r *FeatureRepository) ListPayloads(db *gorm.DB) ([]FeaturePayloadRow, error) {
	var rows []FeaturePayloadRow
	err := db.Model(&securityModel.FeatureSnapshot{}).
		Select("normalized_features").
		Scan(&rows).Error
	return rows, err
}

// CountAttackSurfaceSummary 用于统计特征数据。
func (r *FeatureRepository) CountAttackSurfaceSummary(db *gorm.DB) (AttackSurfaceSummary, error) {
	var summary AttackSurfaceSummary
	row := db.Model(&securityModel.FeatureSnapshot{}).
		Select(`
			COALESCE(SUM(CASE WHEN open_port_count > 0 THEN 1 ELSE 0 END), 0) AS exposed_task_count,
			COALESCE(SUM(CASE WHEN high_risk_port_count > 0 THEN 1 ELSE 0 END), 0) AS high_risk_port_tasks
		`).Row()
	err := row.Scan(&summary.ExposedTaskCount, &summary.HighRiskPortTasks)
	return summary, err
}

// DeleteByTaskID 用于删除特征记录。
func (r *FeatureRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.FeatureSnapshot{}).Error
}
