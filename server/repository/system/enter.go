package system

// RepositoryGroup 聚合系统域下的鉴权与审计两个仓储实例。
// RepositoryGroup 用于聚合系统域与安全域的数据访问实例。
type RepositoryGroup struct {
	AuthRepository  AuthRepository
	AuditRepository AuditRepository
}
