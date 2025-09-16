package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/iveteran/OAuth2WebFlow/model"
	"github.com/iveteran/OAuth2WebFlow/util"
)

type AuthService struct {
	DB *sql.DB
}

func (s *AuthService) InitDB() {
	model.InitClientsTable(s.DB)
	model.InitTokenTable(s.DB)
}

// 生成授权 URL
func (s *AuthService) GetAuthURL(provider, userID, platform, scheme string) (string, error) {
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return "", err
	}
	conf := client.ToConfig()
	state := fmt.Sprintf("%s:%s:%s:%s", provider, userID, platform, scheme)
	return conf.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
		oauth2.SetAuthURLParam("login_hint", userID),
	), nil
}

// 处理回调
func (s *AuthService) HandleCallback(provider, userID, code string) error {
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return err
	}
	conf := client.ToConfig()

	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return err
	}
	if token.RefreshToken == "" {
		return fmt.Errorf("no refresh_token received")
	}

	enc, err := util.Encrypt([]byte(token.RefreshToken))
	if err != nil {
		return err
	}

	return model.SaveToken(s.DB, &model.Token{
		Provider:     provider,
		UserID:       userID,
		RefreshToken: enc,
		UpdatedAt:    time.Now(),
	})
}

// 获取 access_token
func (s *AuthService) GetAccessToken(provider, userID string) (*oauth2.Token, error) {
	fmt.Printf("provider: %s, userID: %s\n", provider, userID)
	client, err := model.GetOAuthClient(s.DB, provider)
	if err != nil {
		return nil, err
	}
	conf := client.ToConfig()
	fmt.Printf("client id: %s\n", conf.ClientID)

	t, err := model.GetToken(s.DB, provider, userID)
	if err != nil {
		return nil, err
	}
	fmt.Printf("RefreshToken: %s\n", t.RefreshToken)
	refreshTokenBytes, err := util.Decrypt(t.RefreshToken)
	if err != nil {
		return nil, err
	}

	src := conf.TokenSource(
		context.Background(),
		&oauth2.Token{
			RefreshToken: string(refreshTokenBytes),
		})
	newToken, err := src.Token()
	if err != nil {
		return nil, err
	}

	// 更新 refresh_token（如果 provider 返回了新的）
	if newToken.RefreshToken != "" && newToken.RefreshToken != string(refreshTokenBytes) {
		enc, _ := util.Encrypt([]byte(newToken.RefreshToken))
		_ = model.SaveToken(
			s.DB,
			&model.Token{
				Provider:     provider,
				UserID:       userID,
				RefreshToken: enc,
				UpdatedAt:    time.Now(),
			})
	}

	return newToken, nil
}
