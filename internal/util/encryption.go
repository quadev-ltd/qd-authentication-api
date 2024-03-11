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

// TODO: unit test

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
func GenerateHash(password string, useSalt bool) ([]byte, *string, error) {
	var salt = ""
	var err error
	if useSalt {
		// Generate salt
		saltLength := 32
		salt, err = GenerateSalt(saltLength)
		if err != nil {
			return nil, nil, err
		}
	}

	// Hash password
	hashedPassword, error := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if error != nil {
		return nil, nil, error
	}

	return hashedPassword, &salt, nil
}
