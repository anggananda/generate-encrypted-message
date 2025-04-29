package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	polyCahchaSecretKey := []byte(os.Getenv("POLYCHACHA_SECRET_KEY"))
	hmacSecretKey := []byte(os.Getenv("HMAC_SECRET_KEY"))

	polyCahchaSecretKey = polyCahchaSecretKey[:chacha20poly1305.KeySize]

	timestamp := time.Now().Unix()

	hmacMessage := fmt.Sprintf("%d", timestamp)
	h := hmac.New(sha512.New, hmacSecretKey)
	h.Write([]byte(hmacMessage))
	hmacHex := fmt.Sprintf("%x", h.Sum(nil))

	messageToEncrypt := fmt.Sprintf("%s:%d", hmacHex, timestamp)

	encryptedMessage, err := EncryptPolyChaCha20(messageToEncrypt, polyCahchaSecretKey)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Println("Encrypted Message for Request Data Recap: ")
	fmt.Println(encryptedMessage)
}

func EncryptPolyChaCha20(message string, key []byte) (string, error) {
	if len(key) != chacha20poly1305.KeySize {
		return "", fmt.Errorf("invalid key size, must be 32 bytes")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, []byte(message), nil)

	encryptedMessage := append(nonce, ciphertext...)

	return base64.StdEncoding.EncodeToString(encryptedMessage), nil
}
