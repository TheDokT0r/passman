package password

import (
	"fmt"
	errors_handler "passman/internal/errorHandling"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 72)
	return string(bytes), err
}

func VerifyPassword(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CreateNewPassword() string {
	fmt.Print("Enter new password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	errors_handler.Handling(err)

	fmt.Println()
	return string(bytePassword)
}
