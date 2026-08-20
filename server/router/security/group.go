package security

// RouterGroup 用于聚合系统域与安全域的路由注册器。
// 每个字段对应一类资源的 URL 分组（tasks/dashboard/alerts/configs/records/flow-monitor）。
type RouterGroup struct {
	TaskRouter        TaskRouter
	DashboardRouter   DashboardRouter
	AlertRouter       AlertRouter
	ConfigRouter      ConfigRouter
	RecordRouter      RecordRouter
	FlowMonitorRouter FlowMonitorRouter
}
