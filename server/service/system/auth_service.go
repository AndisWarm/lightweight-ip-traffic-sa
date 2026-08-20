package system

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	modelSystem "lightweight-ip-traffic-sa/server/model/system"
	req "lightweight-ip-traffic-sa/server/model/system/request"
	res "lightweight-ip-traffic-sa/server/model/system/response"
	repositorySystem "lightweight-ip-traffic-sa/server/repository/system"
	"lightweight-ip-traffic-sa/server/utils"
)

// AuthService 用于编排系统管理模块的业务流程。
type AuthService struct {
	repo repositorySystem.AuthRepository
}

// NewAuthService 用于创建并返回新的业务实例。
func NewAuthService() AuthService {
	return AuthService{
		repo: repositorySystem.AuthRepository{},
	}
}

// Login 用于编排鉴权服务流程。
func (s *AuthService) Login(input req.LoginRequest, ip string, userAgent string) (res.LoginResponse, error) {
	user, err := s.repo.FindUserByUsername(input.Username)
	if err != nil {
		_ = s.repo.CreateLoginLog(&modelSystem.SysLoginLog{
			Username:     input.Username,
			IP:           ip,
			UserAgent:    userAgent,
			Status:       false,
			ErrorMessage: "用户名不存在或密码错误",
		})
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return res.LoginResponse{}, errors.New("用户名不存在或密码错误")
		}
		return res.LoginResponse{}, err
	}

	if !user.Enable {
		_ = s.repo.CreateLoginLog(&modelSystem.SysLoginLog{
			Username:     user.Username,
			IP:           ip,
			UserAgent:    userAgent,
			Status:       false,
			ErrorMessage: "用户已被禁用",
		})
		return res.LoginResponse{}, errors.New("用户已被禁用")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		_ = s.repo.CreateLoginLog(&modelSystem.SysLoginLog{
			Username:     user.Username,
			IP:           ip,
			UserAgent:    userAgent,
			Status:       false,
			ErrorMessage: "用户名不存在或密码错误",
		})
		return res.LoginResponse{}, errors.New("用户名不存在或密码错误")
	}

	token, err := utils.GenerateToken(utils.TokenClaims{
		UserID:      user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		RoleCode:    user.RoleCode,
	})
	if err != nil {
		return res.LoginResponse{}, err
	}

	if err := s.repo.CreateLoginLog(&modelSystem.SysLoginLog{
		Username:     user.Username,
		IP:           ip,
		UserAgent:    userAgent,
		Status:       true,
		ErrorMessage: "登录成功",
	}); err != nil {
		return res.LoginResponse{}, err
	}

	return res.LoginResponse{
		Token: token,
		User: res.UserInfo{
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			RoleCode:    user.RoleCode,
			RoleName:    utils.GetRoleName(user.RoleCode),
			Enable:      user.Enable,
			CreatedAt:   user.CreatedAt,
		},
	}, nil
}

// Logout 用于编排鉴权服务流程。
func (s *AuthService) Logout(token string, username string) error {
	if token == "" {
		return nil
	}
	return s.repo.AddTokenToBlacklist(token, username)
}

// GetUserInfo 用于查询鉴权详情并组装响应。
func (s *AuthService) GetUserInfo(userID uint64) (res.UserInfoResponse, error) {
	user, err := s.repo.FindUserByID(userID)
	if err != nil {
		return res.UserInfoResponse{}, err
	}
	return res.UserInfoResponse{
		User: res.UserInfo{
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			RoleCode:    user.RoleCode,
			RoleName:    utils.GetRoleName(user.RoleCode),
			Enable:      user.Enable,
			CreatedAt:   user.CreatedAt,
		},
	}, nil
}

// ListUsers 用于查询鉴权列表并组装响应。
func (s *AuthService) ListUsers() (res.UserListResponse, error) {
	users, err := s.repo.ListUsers()
	if err != nil {
		return res.UserListResponse{}, err
	}
	items := make([]res.UserListItem, 0, len(users))
	for _, user := range users {
		items = append(items, res.UserListItem{
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			RoleCode:    user.RoleCode,
			RoleName:    utils.GetRoleName(user.RoleCode),
			Enable:      user.Enable,
			CreatedAt:   user.CreatedAt,
		})
	}
	return res.UserListResponse{List: items}, nil
}

// CreateUser 用于创建鉴权并触发后续流程。
func (s *AuthService) CreateUser(input req.CreateUserRequest) error {
	if _, err := s.repo.FindUserByUsername(input.Username); err == nil {
		return errors.New("用户名已存在")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	if !utils.IsValidRoleCode(input.RoleCode) {
		return fmt.Errorf("角色不存在: %s", input.RoleCode)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	enable := true
	if input.Enable != nil {
		enable = *input.Enable
	}

	user := &modelSystem.SysUser{
		Username:     input.Username,
		PasswordHash: string(passwordHash),
		DisplayName:  input.DisplayName,
		RoleCode:     input.RoleCode,
		Enable:       enable,
	}
	if err := s.repo.CreateUser(user); err != nil {
		return err
	}
	return nil
}

// UpdateUserStatus 用于编排鉴权服务流程。
func (s *AuthService) UpdateUserStatus(id uint64, enable bool) error {
	return s.repo.UpdateUserStatus(id, enable)
}

// ResetPassword 用于编排鉴权服务流程。
func (s *AuthService) ResetPassword(id uint64, password string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.repo.UpdatePassword(id, string(passwordHash))
}

// IsTokenBlacklisted 用于编排鉴权服务流程。
func (s *AuthService) IsTokenBlacklisted(token string) (bool, error) {
	return s.repo.IsTokenBlacklisted(token)
}
