package system

import (
	modelSystem "lightweight-ip-traffic-sa/server/model/system"

	"lightweight-ip-traffic-sa/server/global"
)

// AuditRepository 用于封装系统管理模块的数据持久化访问。
type AuditRepository struct{}

// ListLoginLogs 用于查询审计列表。
func (r *AuditRepository) ListLoginLogs(limit int) ([]modelSystem.SysLoginLog, error) {
	var rows []modelSystem.SysLoginLog
	query := global.DB.Model(&modelSystem.SysLoginLog{}).Order("created_at DESC").Order("id DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Find(&rows).Error
	return rows, err
}
