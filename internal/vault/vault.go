package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	errors_handler "passman/internal/errorHandling"
	"path/filepath"

	"golang.org/x/crypto/nacl/secretbox"
)

type VaultProp struct {
	name  string
	value string
}

const VAULT_LOCATION = "~/.passman/.vault"

func CreateVault(password string) {
	// Expand the user's home directory symbol "~"
	expandedPath, err := expandPath(VAULT_LOCATION)
	if err != nil {
		panic(fmt.Sprintf("Error expanding path: %s", err))
	}

	// Get the directory path
	vaultDir := filepath.Dir(expandedPath)

	// Check if the directory exists, and create it if not
	if _, err := os.Stat(vaultDir); os.IsNotExist(err) {
		err := os.MkdirAll(vaultDir, 0700) // 0700 is read/write/execute for owner only
		if err != nil {
			panic(fmt.Sprintf("Error creating directory: %s", err))
		}
		fmt.Println("Created directory:", vaultDir)
	}

	// Now you can safely check for and create the file
	if !fileExists(expandedPath) {
		file, err := os.Create(expandedPath)
		if err != nil {
			panic(fmt.Sprintf("Error while creating file: %s", err))
		}
		defer file.Close()
		fmt.Println("Vault file created.")
	} else {
		fmt.Println("Vault file already exists.")
	}
	var vaultProps [0]VaultProp
	vaultPropsByte, err := json.Marshal(&vaultProps)
	errors_handler.Handling(err)

	var key [32]byte
	copy(key[:], []byte(password))

	encryptedData := Encrypt(&key, vaultPropsByte)
	errors_handler.Handling(err)

	err = os.WriteFile(expandedPath, []byte(encryptedData), 0644)
	errors_handler.Handling(err)

	fmt.Println("Vault Created")
}

func AddDataToVault(password string, newVaultProp VaultProp) {
	vault := GetVaultData(password)

	vault = append(vault, newVaultProp)

	vaultByte, err := json.Marshal(&vault)
	errors_handler.Handling(err)

	var key [32]byte
	copy(key[:], []byte(password))

	result := Encrypt(&key, vaultByte)
	errors_handler.Handling(err)
	os.WriteFile(VAULT_LOCATION, []byte(result), 0644)
}

func GetVaultData(password string) []VaultProp {
	val, err := os.ReadFile(VAULT_LOCATION)
	errors_handler.Handling(err)

	var key [32]byte
	copy(key[:], []byte(password))
	decryptedValue, _ := Decrypt(&key, val)

	var vault []VaultProp

	err = json.Unmarshal([]byte(decryptedValue), &vault)
	errors_handler.Handling(err)

	return vault
}

func Encrypt(key *[32]byte, data []byte) []byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, key)
	return encrypted
}

// Decrypt decrypts data using a secretbox.
func Decrypt(key *[32]byte, data []byte) ([]byte, bool) {
	var nonce [24]byte
	copy(nonce[:], data[:24])

	decrypted, ok := secretbox.Open(nil, data[24:], &nonce, key)
	return decrypted, ok
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	// Return false if it's a directory
	return !info.IsDir()
}

func expandPath(path string) (string, error) {
	if len(path) > 1 && path[0:1] == "~" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(homeDir, path[1:]), nil
	}
	return path, nil
}
