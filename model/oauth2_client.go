package model

import (
	"database/sql"
	"strings"

	"golang.org/x/oauth2"
)

type OAuthClient struct {
	Provider     string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       string
	AuthURL      string
	TokenURL     string
}

func InitClientsTable(db *sql.DB) error {
	// 配置表
	_, err := db.Exec(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
		provider TEXT PRIMARY KEY,
		client_id TEXT,
		client_secret TEXT,
		redirect_uri TEXT,
		scopes TEXT,
		auth_url TEXT,
		token_url TEXT
	)`)
	return err
}

func (c *OAuthClient) ToConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURI,
		Scopes:       strings.Split(c.Scopes, ","),
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.AuthURL,
			TokenURL: c.TokenURL,
		},
	}
}

func GetOAuthClient(db *sql.DB, provider string) (*OAuthClient, error) {
	row := db.QueryRow(`SELECT provider, client_id, client_secret,
	redirect_uri, scopes, auth_url, token_url
	FROM oauth_clients
	WHERE provider=?`,
		provider)
	c := &OAuthClient{}
	if err := row.Scan(
		&c.Provider,
		&c.ClientID,
		&c.ClientSecret,
		&c.RedirectURI,
		&c.Scopes,
		&c.AuthURL,
		&c.TokenURL); err != nil {
		return nil, err
	}
	return c, nil
}
