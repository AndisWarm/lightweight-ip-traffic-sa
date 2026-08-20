package security

import "errors"

// ServiceErrorCategory 用于限定ServiceErrorCategory分类取值。
type ServiceErrorCategory string

// 错误类别直接映射到对外响应的语义（参数错/未认证/无权限/冲突/不存在/外部依赖/内部错误），
// 上层根据类别决定 HTTP 状态码和是否重试，而不是靠错误字符串做判断。
const (
	ServiceErrorCategoryInvalidArgument    ServiceErrorCategory = "invalid_argument"
	ServiceErrorCategoryUnauthenticated    ServiceErrorCategory = "unauthenticated"
	ServiceErrorCategoryPermissionDenied   ServiceErrorCategory = "permission_denied"
	ServiceErrorCategoryConflict           ServiceErrorCategory = "conflict"
	ServiceErrorCategoryNotFound           ServiceErrorCategory = "not_found"
	ServiceErrorCategoryExternalDependency ServiceErrorCategory = "external_dependency"
	ServiceErrorCategoryInternal           ServiceErrorCategory = "internal"
)

// ServiceError 用于表达Service错误信息。
type ServiceError struct {
	Category ServiceErrorCategory
	Message  string
	Cause    error
}

// Error 用于返回当前错误的可读描述。
func (e *ServiceError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return ""
}

// Unwrap 用于暴露底层错误以支持 errors 包判定。
func (e *ServiceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NewServiceError 用于创建并返回新的业务实例。
func NewServiceError(category ServiceErrorCategory, message string) *ServiceError {
	return &ServiceError{
		Category: category,
		Message:  message,
	}
}

// WrapServiceError 用于包装ServiceError。
func WrapServiceError(category ServiceErrorCategory, message string, cause error) *ServiceError {
	return &ServiceError{
		Category: category,
		Message:  message,
		Cause:    cause,
	}
}

// ResolveServiceErrorCategory 用于解析ServiceErrorCategory。
func ResolveServiceErrorCategory(err error) ServiceErrorCategory {
	if err == nil {
		return ""
	}

	// 优先 errors.As 沿 Unwrap 链找回 ServiceError 的类别；找不到再按哨兵错误兜底，
	// 最后归类为内部错误。这样即使错误被 fmt.Errorf("%w") 多层包装也能正确分类。
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) {
		return serviceErr.Category
	}
	if errors.Is(err, ErrExternalProviderUnavailable) {
		return ServiceErrorCategoryExternalDependency
	}
	return ServiceErrorCategoryInternal
}

// ResolveServiceErrorMessage 用于解析ServiceErrorMessage。
func ResolveServiceErrorMessage(err error, fallback string) string {
	if err == nil {
		return fallback
	}

	// 优先暴露面向用户的友好 Message（避免把内部实现细节/底层错误直接抛给前端），
	// 拿不到友好消息时退回 fallback，最后才用原始错误文本兜底。
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) && serviceErr.Message != "" {
		return serviceErr.Message
	}
	if fallback != "" {
		return fallback
	}
	return err.Error()
}
