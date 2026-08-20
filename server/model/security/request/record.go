package request

// RecordListQuery 用于映射记录ListQuery数据库记录。
type RecordListQuery struct {
	Page      int    `form:"page"`
	PageSize  int    `form:"pageSize"`
	EventType string `form:"eventType"`
	Keyword   string `form:"keyword"`
	CreatedBy string `form:"-"`
}
