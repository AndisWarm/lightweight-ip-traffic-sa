package system

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"

	responseSecurity "lightweight-ip-traffic-sa/server/model/security/response"
	req "lightweight-ip-traffic-sa/server/model/system/request"
	serviceSystem "lightweight-ip-traffic-sa/server/service/system"
	"lightweight-ip-traffic-sa/server/utils"
)

// AuthApi 用于承接系统管理模块的 HTTP 请求处理。
type AuthApi struct{}

var authService = serviceSystem.NewAuthService()

// Login 用于处理用户登录接口请求。
func (a *AuthApi) Login(c *gin.Context) {
	var input req.LoginRequest
	// 解析登录表单；绑定失败时按字段（用户名/密码）给出具体提示，而不是笼统的"格式错误"。
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail(resolveLoginBindError(err)))
		return
	}
	// 把客户端 IP 与 User-Agent 一并传给 service，用于记录登录日志（安全审计）。
	result, err := authService.Login(input, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		// 登录失败统一回 401；具体是"账号密码错"还是"被禁用"由 resolveLoginError 决定。
		c.JSON(http.StatusUnauthorized, responseSecurity.Fail(resolveLoginError(err)))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(result))
}

// Logout 用于处理用户登出接口请求。
func (a *AuthApi) Logout(c *gin.Context) {
	// 从上下文取登录态；JWTAuth 已保证鉴权通过，这里取出用户名用于定位黑名单记录。
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
		return
	}
	// 把当前 token 写入黑名单（存 SHA256 哈希），使该 token 退出后立即失效。
	if err := authService.Logout(utils.ExtractToken(c), claims.Username); err != nil {
		c.JSON(http.StatusInternalServerError, responseSecurity.Fail("退出登录失败，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(gin.H{"success": true}))
}

// GetCurrentUser 用于处理当前用户信息查询接口请求。
func (a *AuthApi) GetCurrentUser(c *gin.Context) {
	// 身份从 claims 取，无需前端传参；拿 UserID 再查库得到完整用户信息。
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
		return
	}
	result, err := authService.GetUserInfo(claims.UserID)
	if err != nil {
		statusCode, message := resolveGetUserInfoError(err)
		c.JSON(statusCode, responseSecurity.Fail(message))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(result))
}

// ListUsers 用于处理用户列表查询接口请求。
func (a *AuthApi) ListUsers(c *gin.Context) {
	// 角色校验已在路由层用 RequireRoles("ADMIN") 拦截，handler 内无需再判断角色。
	result, err := authService.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, responseSecurity.Fail("获取用户列表失败，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(result))
}

// CreateUser 用于处理用户创建接口请求。
func (a *AuthApi) CreateUser(c *gin.Context) {
	var input req.CreateUserRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail(resolveCreateUserBindError(err)))
		return
	}
	if err := authService.CreateUser(input); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail(resolveCreateUserError(err)))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(gin.H{"success": true}))
}

// UpdateUserStatus 用于处理用户状态更新接口请求。
func (a *AuthApi) UpdateUserStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail("无效的用户 ID"))
		return
	}
	var input req.UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail("用户状态参数不合法"))
		return
	}
	// 更新失败时区分"用户不存在"(404)与其它服务端错误(500)。
	if err := authService.UpdateUserStatus(id, input.Enable); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, responseSecurity.Fail("用户不存在"))
			return
		}
		c.JSON(http.StatusInternalServerError, responseSecurity.Fail("更新用户状态失败，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(gin.H{"success": true}))
}

// ResetPassword 用于处理用户密码重置接口请求。
func (a *AuthApi) ResetPassword(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail("无效的用户 ID"))
		return
	}
	var input req.ResetPasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail(resolveResetPasswordBindError(err)))
		return
	}
	// 重置失败同样区分"用户不存在"(404)与其它服务端错误(500)。
	if err := authService.ResetPassword(id, input.Password); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, responseSecurity.Fail("用户不存在"))
			return
		}
		c.JSON(http.StatusInternalServerError, responseSecurity.Fail("重置密码失败，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(gin.H{"success": true}))
}

// resolveLoginBindError 用于解析LoginBindError。
func resolveLoginBindError(err error) string {
	// 把 validator 的字段级校验错误翻译成用户能看懂的中文提示（按字段名分发）。
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		for _, validationErr := range validationErrors {
			switch validationErr.Field() {
			case "Username":
				return "用户名至少需要 3 个字符"
			case "Password":
				return "密码至少需要 6 个字符"
			}
		}
	}
	return "登录参数格式错误"
}

// resolveLoginError 用于解析LoginError。
func resolveLoginError(err error) string {
	// 只对可预期的业务错误透出原始文案，其它错误一律笼统提示，
	// 避免把内部异常细节（SQL、堆栈等）泄露给客户端。
	switch err.Error() {
	case "用户名不存在或密码错误", "用户已被禁用":
		return err.Error()
	default:
		return "登录失败，请稍后重试"
	}
}

// resolveGetUserInfoError 用于解析Get用户信息Error。
func resolveGetUserInfoError(err error) (int, string) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, "当前用户不存在或已被删除"
	}
	return http.StatusInternalServerError, "获取当前用户信息失败，请稍后重试"
}

// resolveCreateUserBindError 用于解析Create用户BindError。
func resolveCreateUserBindError(err error) string {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		for _, validationErr := range validationErrors {
			switch validationErr.Field() {
			case "Username":
				return "用户名至少需要 3 个字符"
			case "Password":
				return "密码至少需要 6 个字符"
			case "DisplayName":
				return "显示名称至少需要 2 个字符"
			case "RoleCode":
				return "角色编码不能为空"
			}
		}
	}
	return "创建用户参数格式错误"
}

// resolveCreateUserError 用于解析Create用户Error。
func resolveCreateUserError(err error) string {
	switch err.Error() {
	case "用户名已存在":
		return err.Error()
	default:
		// service 返回的"角色不存在"可能带具体角色名后缀，用前缀匹配判断并透出。
		if len(err.Error()) >= len("角色不存在") && err.Error()[:len("角色不存在")] == "角色不存在" {
			return err.Error()
		}
		return "创建用户失败，请稍后重试"
	}
}

// resolveResetPasswordBindError 用于解析ResetPasswordBindError。
func resolveResetPasswordBindError(err error) string {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		return "密码至少需要 6 个字符"
	}
	return "重置密码参数格式错误"
}
