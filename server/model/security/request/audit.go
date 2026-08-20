package request

// AuditLogQuery 用于映射审计LogQuery数据库记录。
type AuditLogQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"pageSize"`
	Category string `form:"category"`
	Action   string `form:"action"`
	Actor    string `form:"actor"`
	Status   string `form:"status"`
}
