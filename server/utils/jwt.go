package utils

import (
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"lightweight-ip-traffic-sa/server/global"
)

var (
	ErrMissingToken = errors.New("未登录或缺少令牌")
	ErrInvalidToken = errors.New("令牌无效")
)

// TokenClaims 用于承载TokenClaims数据。
type TokenClaims struct {
	UserID      uint64 `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	RoleCode    string `json:"roleCode"`
	jwt.RegisteredClaims
}

// GenerateToken 用于生成Token。
func GenerateToken(input TokenClaims) (string, error) {
	expireAt := time.Now().Add(24 * time.Hour)
	claims := TokenClaims{
		UserID:      input.UserID,
		Username:    input.Username,
		DisplayName: input.DisplayName,
		RoleCode:    input.RoleCode,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   input.Username,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(global.Config.App.JWTSecret))
}

// ParseToken 用于解析输入数据并转换为内部模型。
func ParseToken(tokenString string) (*TokenClaims, error) {
	tokenString = strings.TrimSpace(strings.TrimPrefix(tokenString, "Bearer "))
	if tokenString == "" {
		return nil, ErrMissingToken
	}
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(global.Config.App.JWTSecret), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ExtractToken 用于提取请求、令牌或流量中的关键信息。
func ExtractToken(c *gin.Context) string {
	if token := c.GetHeader("Authorization"); token != "" {
		return token
	}
	return c.GetHeader("x-token")
}
