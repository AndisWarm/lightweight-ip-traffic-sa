package system

// ServiceGroup 用于聚合系统域与安全域的业务服务实例。
type ServiceGroup struct {
	AuthService  AuthService
	AuditService AuditService
}

// NewServiceGroup 用于创建并返回新的业务实例。
func NewServiceGroup() ServiceGroup {
	return ServiceGroup{
		AuthService:  NewAuthService(),
		AuditService: NewAuditService(),
	}
}
