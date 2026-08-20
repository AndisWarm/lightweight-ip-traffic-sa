package request

// LoginRequest 用于承载Login接口的请求参数。
// binding 标签在 Gin 的参数绑定阶段做长度/必填校验，非法入参到不了业务层。
type LoginRequest struct {
	Username string `json:"username" binding:"required,min=3"`
	Password string `json:"password" binding:"required,min=6"`
}

// CreateUserRequest 用于承载Create用户接口的请求参数。
type CreateUserRequest struct {
	Username    string `json:"username" binding:"required,min=3"`
	Password    string `json:"password" binding:"required,min=6"`
	DisplayName string `json:"displayName" binding:"required,min=2"`
	RoleCode    string `json:"roleCode" binding:"required"`
	// 用指针区分"未传"(nil) 与 "false"，避免零值被当成禁用
	Enable      *bool  `json:"enable"`
}

// UpdateUserStatusRequest 用于承载Update用户Status接口的请求参数。
type UpdateUserStatusRequest struct {
	Enable bool `json:"enable"`
}

// ResetPasswordRequest 用于承载ResetPassword接口的请求参数。
type ResetPasswordRequest struct {
	Password string `json:"password" binding:"required,min=6"`
}
