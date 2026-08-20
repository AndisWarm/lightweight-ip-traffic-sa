package utils

const (
	RoleAdmin   = "ADMIN"
	RoleManager = "MANAGER"
	RoleUser    = "USER"
)

// GetRoleName 用于执行Get角色名称流程。
func GetRoleName(roleCode string) string {
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
	switch roleCode {
	case RoleAdmin, RoleManager, RoleUser:
		return true
	default:
		return false
	}
}
