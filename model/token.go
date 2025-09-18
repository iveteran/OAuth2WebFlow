package model

import (
	"database/sql"
	"time"
)

type Token struct {
	Provider     string
	UserID       string
	RefreshToken string // encrypted
	UpdatedAt    time.Time
}

func InitTokenTable(db *sql.DB) error {
	// token 表
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		provider TEXT,
		user_id TEXT,
		refresh_token TEXT, -- encrypted base64
		updated_at DATETIME,
		UNIQUE(provider, user_id)
	)`)
	return err
}

func SaveToken(db *sql.DB, t *Token) error {
	_, err := db.Exec(`
	INSERT INTO tokens(provider, user_id, refresh_token, updated_at)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(provider, user_id) DO UPDATE
	SET refresh_token=excluded.refresh_token, updated_at=excluded.updated_at
	`, t.Provider, t.UserID, t.RefreshToken, t.UpdatedAt)
	return err
}

func GetToken(db *sql.DB, provider, userID string) (*Token, error) {
	row := db.QueryRow(`SELECT provider, user_id, refresh_token, updated_at
	FROM tokens
	WHERE lower(provider)=lower(?) AND lower(user_id)=lower(?)`,
		provider, userID)
	t := &Token{}
	if err := row.Scan(
		&t.Provider,
		&t.UserID,
		&t.RefreshToken,
		&t.UpdatedAt); err != nil {
		return nil, err
	}
	return t, nil
}
