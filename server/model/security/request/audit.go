package request

// AuditLogQuery 是审计日志列表接口的查询入参（URL query），各字段均为可选的等值/模糊筛选条件。
// AuditLogQuery 用于映射审计LogQuery数据库记录。
type AuditLogQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"pageSize"`
	Category string `form:"category"`
	Action   string `form:"action"`
	Actor    string `form:"actor"`
	Status   string `form:"status"`
}
