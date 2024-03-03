package util

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// GenerateSalt generates a random salt of the given length
func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, error := rand.Read(salt)
	if error != nil {
		return "", error
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// GenerateVerificationToken generates a random verification token
func GenerateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	date := time.Now().Format("20060102")

	dateBytes := []byte(date)
	tokenBytes := append(dateBytes, b...)

	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

// GenerateHash generates a hash of the given password
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
