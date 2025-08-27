package main

import (
	"errors"
	"fmt"
	"os"
	"passman/internal/password"
	"passman/internal/vault"
)

func main() {
	if _, err := os.Stat(vault.VAULT_LOCATION); errors.Is(err, os.ErrNotExist) {
		fmt.Println("It seems like you don't have a vault yet.")
		password := password.CreateNewPassword()
		vault.CreateVault(password)
	}
}
