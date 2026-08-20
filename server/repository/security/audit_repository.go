package security

import (
	"strings"

	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"

	"gorm.io/gorm"
)

// AuditRepository 用于封装安全态势模块的数据持久化访问。
type AuditRepository struct{}

// Create 用于写入审计记录。
func (r *AuditRepository) Create(db *gorm.DB, record *securityModel.AuditLog) error {
	return db.Create(record).Error
}

// List 用于查询审计列表。
func (r *AuditRepository) List(db *gorm.DB, query requestModel.AuditLogQuery) ([]securityModel.AuditLog, int64, error) {
	base := db.Model(&securityModel.AuditLog{})
	if value := strings.TrimSpace(query.Category); value != "" {
		base = base.Where("category = ?", value)
	}
	if value := strings.TrimSpace(query.Action); value != "" {
		base = base.Where("action = ?", value)
	}
	if value := strings.TrimSpace(query.Actor); value != "" {
		base = base.Where("actor LIKE ?", "%"+value+"%")
	}
	if value := strings.TrimSpace(query.Status); value != "" {
		base = base.Where("status = ?", value)
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []securityModel.AuditLog
	err := base.Order("created_at DESC").Order("id DESC").
		Offset((query.Page - 1) * query.PageSize).
		Limit(query.PageSize).
		Find(&rows).Error
	return rows, total, err
}

// DistinctCategories 用于访问审计持久化数据。
func (r *AuditRepository) DistinctCategories(db *gorm.DB) ([]string, error) {
	var rows []string
	err := db.Model(&securityModel.AuditLog{}).
		Distinct("category").
		Order("category ASC").
		Pluck("category", &rows).Error
	return rows, err
}
