package system

// RouterGroup 用于聚合系统域与安全域的路由注册器。
// 系统域只有鉴权(auth)与审计(audit)两类路由，均挂在 /system 前缀下。
type RouterGroup struct {
	AuthRouter  AuthRouter
	AuditRouter AuditRouter
}
