package security

// RouterGroup 用于聚合系统域与安全域的路由注册器。
type RouterGroup struct {
	TaskRouter        TaskRouter
	DashboardRouter   DashboardRouter
	AlertRouter       AlertRouter
	ConfigRouter      ConfigRouter
	RecordRouter      RecordRouter
	FlowMonitorRouter FlowMonitorRouter
}
