package security

import (
	"sort"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	repositorySystem "lightweight-ip-traffic-sa/server/repository/system"
	"lightweight-ip-traffic-sa/server/utils"
)

// AuditService 用于编排安全态势模块的业务流程。
type AuditService struct{}

// ListAuditLogs 用于查询审计列表并组装响应。
func (s *AuditService) ListAuditLogs(query requestModel.AuditLogQuery) (responseModel.PagedAuditLogResponse, error) {
	query.Page = utils.NormalizePage(query.Page)
	query.PageSize = utils.NormalizePageSize(query.PageSize)

	rows, _, err := repository.RepositoryGroupApp.SecurityRepositoryGroup.AuditRepository.List(global.DB, query)
	if err != nil {
		return responseModel.PagedAuditLogResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取审计日志失败，请稍后重试", err)
	}
	categories, err := repository.RepositoryGroupApp.SecurityRepositoryGroup.AuditRepository.DistinctCategories(global.DB)
	if err != nil {
		return responseModel.PagedAuditLogResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取审计日志失败，请稍后重试", err)
	}

	items := make([]responseModel.AuditLogItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, responseModel.AuditLogItem{
			ID:          row.ID,
			Category:    row.Category,
			Action:      row.Action,
			Actor:       row.Actor,
			RoleCode:    row.RoleCode,
			TargetType:  row.TargetType,
			TargetID:    row.TargetID,
			TargetLabel: row.TargetLabel,
			Status:      row.Status,
			Summary:     row.Summary,
			IP:          row.IP,
			UserAgent:   row.UserAgent,
			CreatedAt:   row.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	if strings.TrimSpace(query.Category) == "" || strings.EqualFold(strings.TrimSpace(query.Category), "LOGIN") {
		loginRows, loginErr := (&repositorySystem.AuditRepository{}).ListLoginLogs(query.PageSize)
		if loginErr == nil {
			for _, row := range loginRows {
				status := "SUCCESS"
				if !row.Status {
					status = "FAILED"
				}
				items = append(items, responseModel.AuditLogItem{
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
			if !containsString(categories, "LOGIN") {
				categories = append(categories, "LOGIN")
				sort.Strings(categories)
			}
		}
	}
	sortAuditItems(items)

	return responseModel.PagedAuditLogResponse{
		Page:       query.Page,
		PageSize:   query.PageSize,
		Total:      int64(len(items)),
		Items:      items,
		Categories: categories,
	}, nil
}

// sortAuditItems 用于排序审计Items。
func sortAuditItems(items []responseModel.AuditLogItem) {
	sort.Slice(items, func(i, j int) bool {
		left, leftErr := time.Parse("2006-01-02 15:04:05", items[i].CreatedAt)
		right, rightErr := time.Parse("2006-01-02 15:04:05", items[j].CreatedAt)
		if leftErr != nil || rightErr != nil {
			return items[i].CreatedAt > items[j].CreatedAt
		}
		return left.After(right)
	})
}

// containsString 用于判断集合中是否包含String。
func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

// recordSecurityAuditLog 用于记录安全审计Log。
func recordSecurityAuditLog(entry AuditLogEntry) {
	record := buildSecurityAuditLog(entry)
	if record == nil {
		return
	}
	_ = repository.RepositoryGroupApp.SecurityRepositoryGroup.AuditRepository.Create(global.DB, record)
}

// AuditLogEntry 用于承载审计LogEntry配置条目。
type AuditLogEntry struct {
	Category    string
	Action      string
	Actor       string
	RoleCode    string
	TargetType  string
	TargetID    string
	TargetLabel string
	Status      string
	Summary     string
	Detail      string
	IP          string
	UserAgent   string
}

// buildSecurityAuditLog 用于构建安全审计Log。
func buildSecurityAuditLog(entry AuditLogEntry) *securityModel.AuditLog {
	category := strings.TrimSpace(entry.Category)
	action := strings.TrimSpace(entry.Action)
	if category == "" || action == "" {
		return nil
	}
	return &securityModel.AuditLog{
		Category:    category,
		Action:      action,
		Actor:       strings.TrimSpace(entry.Actor),
		RoleCode:    strings.TrimSpace(entry.RoleCode),
		TargetType:  strings.TrimSpace(entry.TargetType),
		TargetID:    strings.TrimSpace(entry.TargetID),
		TargetLabel: strings.TrimSpace(entry.TargetLabel),
		Status:      fallbackString(strings.TrimSpace(entry.Status), "SUCCESS"),
		Summary:     strings.TrimSpace(entry.Summary),
		Detail:      fallbackString(strings.TrimSpace(entry.Detail), "{}"),
		IP:          strings.TrimSpace(entry.IP),
		UserAgent:   strings.TrimSpace(entry.UserAgent),
	}
}
