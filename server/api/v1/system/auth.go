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
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, responseSecurity.Fail(resolveLoginBindError(err)))
		return
	}
	result, err := authService.Login(input, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.JSON(http.StatusUnauthorized, responseSecurity.Fail(resolveLoginError(err)))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(result))
}

// Logout 用于处理用户登出接口请求。
func (a *AuthApi) Logout(c *gin.Context) {
	value, _ := c.Get("claims")
	claims, _ := value.(*utils.TokenClaims)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, responseSecurity.Fail("未登录或登录状态已失效"))
		return
	}
	if err := authService.Logout(utils.ExtractToken(c), claims.Username); err != nil {
		c.JSON(http.StatusInternalServerError, responseSecurity.Fail("退出登录失败，请稍后重试"))
		return
	}
	c.JSON(http.StatusOK, responseSecurity.Ok(gin.H{"success": true}))
}

// GetCurrentUser 用于处理当前用户信息查询接口请求。
func (a *AuthApi) GetCurrentUser(c *gin.Context) {
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
