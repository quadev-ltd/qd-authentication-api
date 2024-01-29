package util

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, error := rand.Read(salt)
	if error != nil {
		return "", error
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func GenerateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)
	return token, nil
}

func GenerateHash(password string) ([]byte, *string, error) {
	// Generate salt
	saltLength := 32
	salt, error := GenerateSalt(saltLength)
	if error != nil {
		return nil, nil, error
	}

	// Hash password
	hashedPassword, error := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if error != nil {
		return nil, nil, error
	}

	return hashedPassword, &salt, nil
}
