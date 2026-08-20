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
	// 前四个字段是业务自带身份信息，直接打进 JWT 载荷，鉴权时无需再查库。
	UserID      uint64 `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	RoleCode    string `json:"roleCode"`
	jwt.RegisteredClaims
}

// GenerateToken 用于生成Token。
func GenerateToken(input TokenClaims) (string, error) {
	// 过期时间硬编码 24 小时：短期有效可缩小 token 泄露后的风险窗口，也迫使定期重登。
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
	// HS256 是对称签名：签发与校验用同一把 JWTSecret，密钥一旦泄露即可伪造任意 token，务必保密。
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(global.Config.App.JWTSecret))
}

// ParseToken 用于解析输入数据并转换为内部模型。
func ParseToken(tokenString string) (*TokenClaims, error) {
	// 兼容标准 "Bearer xxx" 与裸 token 两种传法；TrimPrefix 只去掉一次 Bearer 前缀。
	tokenString = strings.TrimSpace(strings.TrimPrefix(tokenString, "Bearer "))
	if tokenString == "" {
		return nil, ErrMissingToken
	}
	// keyfunc 返回签名密钥供库校验；库同时自动校验过期时间等 RegisteredClaims。
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(global.Config.App.JWTSecret), nil
	})
	// 任何解析失败都统一折叠成 ErrInvalidToken，避免把内部签名错误细节暴露给客户端。
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
