package response

import "time"

// UserInfo 用于映射用户信息数据库记录。
type UserInfo struct {
	ID          uint64    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	RoleCode    string    `json:"roleCode"`
	RoleName    string    `json:"roleName"`
	Enable      bool      `json:"enable"`
	CreatedAt   time.Time `json:"createdAt"`
}

// LoginResponse 用于承载Login接口的响应数据。
type LoginResponse struct {
	// 前端拿到后存本地，后续请求放入 Authorization 头
	Token string   `json:"token"`
	User  UserInfo `json:"user"`
}

// UserInfoResponse 用于承载用户信息接口的响应数据。
type UserInfoResponse struct {
	User UserInfo `json:"user"`
}

// UserListItem 用于承载用户List列表展示条目。
type UserListItem struct {
	ID          uint64    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName"`
	RoleCode    string    `json:"roleCode"`
	RoleName    string    `json:"roleName"`
	Enable      bool      `json:"enable"`
	CreatedAt   time.Time `json:"createdAt"`
}

// UserListResponse 用于承载用户List接口的响应数据。
type UserListResponse struct {
	List []UserListItem `json:"list"`
}
