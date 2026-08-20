package system

// RouterGroup 用于聚合系统域与安全域的路由注册器。
type RouterGroup struct {
	AuthRouter  AuthRouter
	AuditRouter AuditRouter
}
