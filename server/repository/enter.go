package repository

import (
	"lightweight-ip-traffic-sa/server/repository/security"
	repositorySystem "lightweight-ip-traffic-sa/server/repository/system"
)

var RepositoryGroupApp = new(RepositoryGroup)

// RepositoryGroup 用于聚合系统域与安全域的数据访问实例。
type RepositoryGroup struct {
	SecurityRepositoryGroup security.RepositoryGroup
	SystemRepositoryGroup   repositorySystem.RepositoryGroup
}
