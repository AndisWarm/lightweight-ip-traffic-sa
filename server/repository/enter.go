package repository

import (
	"lightweight-ip-traffic-sa/server/repository/security"
	repositorySystem "lightweight-ip-traffic-sa/server/repository/system"
)

// RepositoryGroupApp 是进程级单例，聚合 system 与 security 两个域的所有仓储实例，
// 由 initialize 阶段统一注入，供 service 层通过全局变量取用。
var RepositoryGroupApp = new(RepositoryGroup)

// RepositoryGroup 用于聚合系统域与安全域的数据访问实例。
type RepositoryGroup struct {
	SecurityRepositoryGroup security.RepositoryGroup
	SystemRepositoryGroup   repositorySystem.RepositoryGroup
}
