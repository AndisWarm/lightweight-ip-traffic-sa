package system

// RepositoryGroup 用于聚合系统域与安全域的数据访问实例。
type RepositoryGroup struct {
	AuthRepository  AuthRepository
	AuditRepository AuditRepository
}
