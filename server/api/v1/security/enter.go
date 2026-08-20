package security

// ApiGroup 用于聚合系统域与安全域的接口入口。
// 每个字段对应一类业务接口的 handler，与 router/security 下的路由注册一一对应。
type ApiGroup struct {
	TaskApi        TaskApi
	DashboardApi   DashboardApi
	AlertApi       AlertApi
	ConfigApi      ConfigApi
	RecordApi      RecordApi
	FlowMonitorApi FlowMonitorApi
}
