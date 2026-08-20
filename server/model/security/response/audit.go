package response

// AuditLogItem 用于承载审计Log列表展示条目。
type AuditLogItem struct {
	ID          uint64 `json:"id"`
	Category    string `json:"category"`
	Action      string `json:"action"`
	Actor       string `json:"actor"`
	RoleCode    string `json:"roleCode"`
	TargetType  string `json:"targetType"`
	TargetID    string `json:"targetId"`
	TargetLabel string `json:"targetLabel"`
	Status      string `json:"status"`
	Summary     string `json:"summary"`
	IP          string `json:"ip"`
	UserAgent   string `json:"userAgent"`
	CreatedAt   string `json:"createdAt"`
}

// PagedAuditLogResponse 用于承载Paged审计Log接口的响应数据。
type PagedAuditLogResponse struct {
	Page       int            `json:"page"`
	PageSize   int            `json:"pageSize"`
	Total      int64          `json:"total"`
	Items      []AuditLogItem `json:"items"`
	Categories []string       `json:"categories"`
}
