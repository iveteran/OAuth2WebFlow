package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func getKey() []byte {
	key := os.Getenv("TOKEN_KEY")
	if key == "" {
		panic("TOKEN_KEY not set")
	}
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(getKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func Decrypt(enc string) ([]byte, error) {
	block, err := aes.NewCipher(getKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	ct := data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
