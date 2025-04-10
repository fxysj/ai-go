package service

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type SSOService struct {
	secretKey     string
	tokenDuration time.Duration
}

type UserClaims struct {
	jwt.StandardClaims
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func NewSSOService(secretKey string, tokenDuration time.Duration) *SSOService {
	return &SSOService{
		secretKey:     secretKey,
		tokenDuration: tokenDuration,
	}
}

// Login 处理用户登录并生成JWT token
func (s *SSOService) Login(ctx context.Context, username, password string) (string, error) {
	// TODO: 实现用户验证逻辑
	// 这里应该调用你的用户服务来验证用户名和密码

	// 示例：验证成功后生成token
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(s.tokenDuration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserID:   "user123", // 应该是从数据库获取的用户ID
		Username: username,
		Role:     "user",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateToken 验证JWT token
func (s *SSOService) ValidateToken(ctx context.Context, tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// Logout 处理用户登出
func (s *SSOService) Logout(ctx context.Context, token string) error {
	// TODO: 实现登出逻辑
	// 可以将token加入黑名单或者直接在Redis中删除相关session
	return nil
}

// RefreshToken 刷新JWT token
func (s *SSOService) RefreshToken(ctx context.Context, oldToken string) (string, error) {
	claims, err := s.ValidateToken(ctx, oldToken)
	if err != nil {
		return "", err
	}

	// 创建新的token
	claims.ExpiresAt = time.Now().Add(s.tokenDuration).Unix()
	claims.IssuedAt = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}
