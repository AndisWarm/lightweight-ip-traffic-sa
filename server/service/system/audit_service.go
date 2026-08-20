package system

import (
	"lightweight-ip-traffic-sa/server/model/security/response"
	repositorySystem "lightweight-ip-traffic-sa/server/repository/system"
)

// AuditService 用于编排系统管理模块的业务流程。
type AuditService struct {
	repo repositorySystem.AuditRepository
}

// NewAuditService 用于创建并返回新的业务实例。
func NewAuditService() AuditService {
	return AuditService{repo: repositorySystem.AuditRepository{}}
}

// ListLoginLogs 用于查询审计列表并组装响应。
func (s *AuditService) ListLoginLogs(limit int) ([]response.AuditLogItem, error) {
	rows, err := s.repo.ListLoginLogs(limit)
	if err != nil {
		return nil, err
	}
	items := make([]response.AuditLogItem, 0, len(rows))
	for _, row := range rows {
		status := "SUCCESS"
		if !row.Status {
			status = "FAILED"
		}
		items = append(items, response.AuditLogItem{
			ID:        row.ID,
			Category:  "LOGIN",
			Action:    "SYSTEM_LOGIN",
			Actor:     row.Username,
			Status:    status,
			Summary:   row.ErrorMessage,
			IP:        row.IP,
			UserAgent: row.UserAgent,
			CreatedAt: row.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return items, nil
}
