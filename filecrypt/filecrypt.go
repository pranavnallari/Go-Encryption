package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keySize   = 32
	nonceSize = 12
)

func Encrypt(file string, password []byte) error {
	plaintext, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	salt := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := pbkdf2.Key(password, salt, 4096, keySize, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nil, salt, plaintext, nil)

	outputFile, err := os.Create(file + ".encrypted")
	if err != nil {
		return err
	}
	defer outputFile.Close()

	if _, err := outputFile.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

func Decrypt(file string, password []byte) error {
	ciphertext, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	salt := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	key := pbkdf2.Key(password, salt, 4096, keySize, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := aesgcm.Open(nil, salt, ciphertext, nil)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(file[:len(file)-len(".encrypted")])
	if err != nil {
		return err
	}
	defer outputFile.Close()

	if _, err := outputFile.Write(plaintext); err != nil {
		return err
	}

	return nil
}
