package test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"titkee.com/service" // 请替换为实际的项目路径
)

func TestNewSSOService(t *testing.T) {
	secretKey := "test-secret"
	duration := 24 * time.Hour

	ssoService := service.NewSSOService(secretKey, duration)
	assert.NotNil(t, ssoService, "SSO service should not be nil")
}

func TestSSOService_Login(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid login",
			username: "testuser",
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "Empty username",
			username: "",
			password: "testpass",
			wantErr:  true,
		},
		{
			name:     "Empty password",
			username: "testuser",
			password: "",
			wantErr:  true,
		},
	}

	ssoService := service.NewSSOService("test-secret", 24*time.Hour)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ssoService.Login(ctx, tt.username, tt.password)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestSSOService_ValidateToken(t *testing.T) {
	ssoService := service.NewSSOService("test-secret", 24*time.Hour)
	ctx := context.Background()

	// 首先获取一个有效的token
	token, err := ssoService.Login(ctx, "testuser", "testpass")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	tests := []struct {
		name      string
		token     string
		wantValid bool
	}{
		{
			name:      "Valid token",
			token:     token,
			wantValid: true,
		},
		{
			name:      "Invalid token",
			token:     "invalid-token",
			wantValid: false,
		},
		{
			name:      "Empty token",
			token:     "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ssoService.ValidateToken(ctx, tt.token)
			if tt.wantValid {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				assert.Equal(t, "testuser", claims.Username)
			} else {
				assert.Error(t, err)
				assert.Nil(t, claims)
			}
		})
	}
}

func TestSSOService_RefreshToken(t *testing.T) {
	ssoService := service.NewSSOService("test-secret", 24*time.Hour)
	ctx := context.Background()

	// 获取初始token
	originalToken, err := ssoService.Login(ctx, "testuser", "testpass")
	assert.NoError(t, err)
	assert.NotEmpty(t, originalToken)

	tests := []struct {
		name      string
		token     string
		wantValid bool
	}{
		{
			name:      "Valid token refresh",
			token:     originalToken,
			wantValid: true,
		},
		{
			name:      "Invalid token refresh",
			token:     "invalid-token",
			wantValid: false,
		},
		{
			name:      "Empty token refresh",
			token:     "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newToken, err := ssoService.RefreshToken(ctx, tt.token)
			if tt.wantValid {
				assert.NoError(t, err)
				assert.NotEmpty(t, newToken)
				assert.NotEqual(t, tt.token, newToken)

				// 验证新token是否有效
				claims, err := ssoService.ValidateToken(ctx, newToken)
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			} else {
				assert.Error(t, err)
				assert.Empty(t, newToken)
			}
		})
	}
}

func TestSSOService_Logout(t *testing.T) {
	ssoService := service.NewSSOService("test-secret", 24*time.Hour)
	ctx := context.Background()

	// 获取有效token
	token, err := ssoService.Login(ctx, "testuser", "testpass")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "Valid logout",
			token:   token,
			wantErr: false,
		},
		{
			name:    "Invalid token logout",
			token:   "invalid-token",
			wantErr: true,
		},
		{
			name:    "Empty token logout",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ssoService.Logout(ctx, tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// 验证登出后token是否失效
				_, err := ssoService.ValidateToken(ctx, tt.token)
				assert.Error(t, err)
			}
		})
	}
}
