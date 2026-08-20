package security

// ServiceGroup 用于聚合系统域与安全域的业务服务实例。
type ServiceGroup struct {
	TaskService        TaskService
	DashboardService   DashboardService
	AlertService       AlertService
	ConfigService      ConfigService
	RecordService      RecordService
	FlowMonitorService FlowMonitorService
	AuditService       AuditService
}
