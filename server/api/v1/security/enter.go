package security

// ApiGroup 用于聚合系统域与安全域的接口入口。
type ApiGroup struct {
	TaskApi        TaskApi
	DashboardApi   DashboardApi
	AlertApi       AlertApi
	ConfigApi      ConfigApi
	RecordApi      RecordApi
	FlowMonitorApi FlowMonitorApi
}
