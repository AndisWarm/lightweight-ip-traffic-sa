package request

// RecordListQuery 是历史记录列表接口的查询入参。EventType 区分任务/预警两类记录，
// CreatedBy 由后端从登录态注入（form:"-"），用于数据权限过滤。
// RecordListQuery 用于映射记录ListQuery数据库记录。
type RecordListQuery struct {
	Page      int    `form:"page"`
	PageSize  int    `form:"pageSize"`
	EventType string `form:"eventType"`
	Keyword   string `form:"keyword"`
	CreatedBy string `form:"-"`
}
