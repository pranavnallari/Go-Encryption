package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pranavnallari/go-encrypt/filecrypt"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run Encrypt to encrypt the file, and decrypt to decrypt the file")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("File Encryption")
	fmt.Println("Simple File Encrypter")
	fmt.Println("")
	fmt.Println("Usage : ")
	fmt.Printf("\tgo run . encrypt /path/to/your/file\n")
	fmt.Println("")
	fmt.Println("Commands : ")
	fmt.Println("")
	fmt.Printf("\t encrypt \t Encrypts a file given a password \n")
	fmt.Printf("\t decrypt \t Decrypts a file using the password\n")
	fmt.Printf("\t help\t\tDisplays a help text\n")
	fmt.Println("")
}

func encryptHandle() {
	if len(os.Args) < 3 {
		fmt.Println("Missing Parameters, please provide a filename.")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		fmt.Println("File Not Found!")
		os.Exit(1)
	}
	password := getPassword()
	fmt.Println("\nEncrypting....")
	err := encryptFile(file, password)
	if err != nil {
		fmt.Println("Encryption Error:", err)
		os.Exit(1)
	}
	outputFile := file + ".encrypted"
	fmt.Println("\nFile encrypted successfully. Encrypted file saved as:", outputFile)
}

func decryptHandle() {
	if len(os.Args) < 3 {
		fmt.Println("Missing Parameters, please provide a filename.")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		fmt.Println("File Not Found!")
		os.Exit(1)
	}
	fmt.Println("Enter Password to decrypt:")
	password := getPassword()
	fmt.Println("\nDecrypting....")
	err := decryptFile(file, password)
	if err != nil {
		fmt.Println("Decryption Error:", err)
		os.Exit(1)
	}
	outputFile := removeExtension(file)
	fmt.Println("\nFile decrypted successfully. Decrypted file saved as:", outputFile)
}

func getPassword() []byte {
	fmt.Println("Enter password : ")
	password, _ := term.ReadPassword(0)
	fmt.Println("\nConfirm Password : ")
	confPassword, _ := term.ReadPassword(0)
	if !validatePassword(password, confPassword) {
		fmt.Println("Passwords Do Not Match. Try Again!")
		return getPassword()
	}
	return password
}

func validatePassword(ps1, ps2 []byte) bool {
	return string(ps1) == string(ps2)
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}

func removeExtension(file string) string {
	return file[:len(file)-len(filepath.Ext(file))]
}

func encryptFile(file string, password []byte) error {
	return filecrypt.Encrypt(file, password)
}

func decryptFile(file string, password []byte) error {
	return filecrypt.Decrypt(file, password)
}
