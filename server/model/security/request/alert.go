package request

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
