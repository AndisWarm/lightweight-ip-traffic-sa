package service

import (
	"lightweight-ip-traffic-sa/server/service/security"
	serviceSystem "lightweight-ip-traffic-sa/server/service/system"
)

var ServiceGroupApp = &ServiceGroup{
	SecurityServiceGroup: security.ServiceGroup{},
	SystemServiceGroup:   serviceSystem.NewServiceGroup(),
}

// ServiceGroup 用于聚合系统域与安全域的业务服务实例。
type ServiceGroup struct {
	SecurityServiceGroup security.ServiceGroup
	SystemServiceGroup   serviceSystem.ServiceGroup
}
