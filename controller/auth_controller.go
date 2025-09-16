package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/iveteran/OAuth2WebFlow/service"
	"github.com/iveteran/OAuth2WebFlow/util"
)

type AuthController struct {
	Service    *service.AuthService
	challenges map[string]map[string]string // userId -> challenge -> platform
}

// /authorize?provider=google&user_id=alice[&platform=desktop&challenge=xyz]
func (c *AuthController) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	userID := r.URL.Query().Get("user_id")
	if provider == "" || userID == "" {
		http.Error(w, "error: miss required parameter", http.StatusBadRequest)
		return
	}

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

	url, err := c.Service.GetAuthURL(provider, userID, platform)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// /callback?state=provider:user_id:platform&code=xxx
func (c *AuthController) Callback(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.URL.Query().Get("state"), ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	provider, userID, platform := parts[0], parts[1], parts[2]
	code := r.URL.Query().Get("code")

	if err := c.Service.HandleCallback(provider, userID, code); err != nil {
		http.Error(w, "callback error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if platform == "ios" || platform == "android" {
		// 1. 签发 JWT（有效期 24 小时）
		jwtToken, err := util.GenerateJWT(userID, 24*time.Hour)
		if err != nil {
			http.Error(w, "generate jwt failed", http.StatusInternalServerError)
		}
		// 2. 重定向到 App 的 Deep Link
		redirect := fmt.Sprintf("incontrolchat://auth/callback?jwt=%s&provider=%s&user=%s",
			jwtToken, provider, userID)
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
	userVerified := false
	var jwtToken string
	// 从 Authorization: Bearer <token> 中取出 token
	auth := r.Header.Get("Authorization")
	if auth != "" && len(auth) > 7 && auth[:7] == "Bearer " {
		// 1. 用JWT验证用户
		jwtStr := auth[7:]
		var err error
		userID, err = util.ValidateJWT(jwtStr)
		if err != nil {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		userVerified = true
	} else {
		// 2. 如果用户没有提供JWT，说明App没有(或不支持)通过Deep Link获取到JWT，就用challenge验证用户
		userID = r.URL.Query().Get("user_id")
		challenge := r.URL.Query().Get("challenge")
		//log.Printf("gettoken userID: %s", userID)
		//log.Printf("gettoken challenge: %s", challenge)
		//log.Println(c.challenges)
		if userID != "" && challenge != "" && c.challenges != nil {
			if userChallenges, exists := c.challenges[userID]; exists && userChallenges != nil {
				if _, exists2 := userChallenges[challenge]; exists2 {
					userVerified = true
					// 签发 JWT（有效期 24 小时）
					var err error
					jwtToken, err = util.GenerateJWT(userID, 24*time.Hour)
					if err != nil {
						http.Error(w, "generate jwt failed", http.StatusInternalServerError)
					}
					// challenge只用一次，如果为用户生成了JWT，后续就用JWT验证用户
					delete(c.challenges[userID], challenge)
					if len(c.challenges[userID]) == 0 {
						delete(c.challenges, userID)
					}
				}
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
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"expiry":       token.Expiry,
		"jwt":          jwtToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
