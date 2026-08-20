package utils

// 三级角色权限模型：ADMIN 拥有系统管理权限（用户/审计），MANAGER 负责安全业务管理，USER 为普通业务用户。
const (
	RoleAdmin   = "ADMIN"
	RoleManager = "MANAGER"
	RoleUser    = "USER"
)

// GetRoleName 用于执行Get角色名称流程。
func GetRoleName(roleCode string) string {
	// 把角色编码翻译成展示名；未知编码原样返回，保证前端总能看到可读文本。
	switch roleCode {
	case RoleAdmin:
		return "Admin"
	case RoleManager:
		return "Manager"
	case RoleUser:
		return "User"
	default:
		return roleCode
	}
}

// IsValidRoleCode 用于判断输入是否满足指定条件。
func IsValidRoleCode(roleCode string) bool {
	// 白名单校验：只有三个预定义角色合法，防止接口传入任意角色码导致越权。
	switch roleCode {
	case RoleAdmin, RoleManager, RoleUser:
		return true
	default:
		return false
	}
}
