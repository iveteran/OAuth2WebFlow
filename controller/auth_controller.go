package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/iveteran/OAuth2WebFlow/service"
)

type AuthController struct {
	Service    *service.AuthService
	challenges map[string]map[string]string // userId -> challenge -> platform
}

// /authorize?provider=google&user_id=alice[&scheme=myapp&platform=desktop&challenge=xyz]
func (c *AuthController) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	userID := r.URL.Query().Get("user_id")
	if provider == "" || userID == "" {
		http.Error(w, "error: miss required parameter", http.StatusBadRequest)
		return
	}

	scheme := r.URL.Query().Get("scheme")
	platform := r.URL.Query().Get("platform")
	challenge := r.URL.Query().Get("challenge")
	if challenge != "" {
		if c.challenges == nil {
			c.challenges = make(map[string]map[string]string)
		}
		if c.challenges[userID] == nil {
			c.challenges[userID] = make(map[string]string)
		}
		c.challenges[userID][challenge] = platform
	}
	//log.Printf("auth userID: %s", userID)
	//log.Printf("auth challenge: %s", challenge)
	//log.Println(c.challenges)

	url, err := c.Service.GetAuthURL(provider, userID, platform, scheme)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// /callback?state=provider:user_id:platform:scheme&code=xxx
func (c *AuthController) Callback(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.URL.Query().Get("state"), ":", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	provider, userID, platform, scheme := parts[0], parts[1], parts[2], parts[3]
	code := r.URL.Query().Get("code")

	if err := c.Service.HandleCallback(provider, userID, code); err != nil {
		http.Error(w, "callback error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if platform == "ios" || platform == "android" {
		redirect := fmt.Sprintf("%s://auth/callback?provider=%s&user=%s",
			scheme, provider, userID)
		http.Redirect(w, r, redirect, http.StatusFound)
	} else {
		// 桌面应用不支持从浏览器跳回应用
		fmt.Fprintf(w, "<html><h1>%s login successful! You can close this window.</h1></html>", provider)
	}
}

// /get_token?provider=google[&user_id=xxx&challenge=yyy]
func (c *AuthController) GetToken(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}
	var userID string
	var challenge string
	userVerified := false
	// 如果用户没有提供JWT，说明App没有(或不支持)通过Deep Link获取到JWT，就用challenge验证用户
	userID = r.URL.Query().Get("user_id")
	challenge = r.URL.Query().Get("challenge")
	//log.Printf("getToken userID: %s", userID)
	//log.Printf("getToken challenge: %s", challenge)
	//log.Println(c.challenges)
	if userID != "" && challenge != "" && c.challenges != nil {
		if userChallenges, exists := c.challenges[userID]; exists && userChallenges != nil {
			if _, exists2 := userChallenges[challenge]; exists2 {
				userVerified = true
			}
		}
	}
	if !userVerified {
		http.Error(w, "verifiy user failure: miss JWT or/and challenge", http.StatusUnauthorized)
		return
	}

	token, err := c.Service.GetAccessToken(provider, userID)
	if err != nil {
		http.Error(w, "get token error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    token.TokenType,
		"expires_in":    token.ExpiresIn,
		"expiry":        token.Expiry,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
