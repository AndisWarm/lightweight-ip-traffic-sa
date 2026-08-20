package system

// ApiGroup 用于聚合系统域与安全域的接口入口。
type ApiGroup struct {
	AuthApi  AuthApi
	AuditApi AuditApi
}
