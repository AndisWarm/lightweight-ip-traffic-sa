package request

// AlertListQuery 是预警列表接口的查询入参（URL query）。CreatedBy 不从前端接收（form:"-"），
// 由后端从登录态注入，用于按发起人过滤预警。
// AlertListQuery 用于映射预警ListQuery数据库记录。
type AlertListQuery struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"pageSize"`
	TargetIP   string `form:"targetIp"`
	AlertLevel string `form:"alertLevel"`
	SendStatus string `form:"sendStatus"`
	Channel    string `form:"channel"`
	CreatedBy  string `form:"-"`
}
