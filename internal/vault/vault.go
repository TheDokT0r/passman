package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	errors_handler "passman/internal/errorHandling"
)

type VaultProp struct {
	name  string
	value string
}

const VAULT_LOCATION = "~/.passman/.vault"

func CreateVault(password string) {
	encryptedData := encrypt(password, "[]")

	err := os.WriteFile(VAULT_LOCATION, []byte(encryptedData), 0644)
	errors_handler.Handling(err)

	fmt.Println("Vault Created")
}

func AddDataToVault(password string, newVaultProp VaultProp) {
	vault := GetVaultData(password)

	vault = append(vault, newVaultProp)

	vaultJson, err := json.Marshal(&vault)
	errors_handler.Handling(err)

	result := encrypt(password, string(vaultJson))
	os.WriteFile(VAULT_LOCATION, []byte(result), 0644)
}

func GetVaultData(password string) []VaultProp {
	val, err := os.ReadFile(VAULT_LOCATION)
	errors_handler.Handling(err)
	decryptedValue := decrypt(password, string(val))

	var vault []VaultProp

	err = json.Unmarshal([]byte(decryptedValue), &vault)
	errors_handler.Handling(err)

	return vault
}

func encrypt(password string, value string) string {
	key, err := hex.DecodeString(value)
	errors_handler.Handling(err)

	plainText := []byte(value)

	block, err := aes.NewCipher(key)
	errors_handler.Panic(err)

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(keyString string, stringToDecrypt string) string {
	key, _ := hex.DecodeString(keyString)
	ciphertext, _ := base64.URLEncoding.DecodeString(stringToDecrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}
