package system

// ApiGroup 用于聚合系统域与安全域的接口入口。
// 系统域目前只暴露鉴权(auth)与审计(audit)两组 handler。
type ApiGroup struct {
	AuthApi  AuthApi
	AuditApi AuditApi
}
