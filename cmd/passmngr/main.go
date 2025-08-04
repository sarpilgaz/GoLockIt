package main

import (
	"fmt"
	"passwordManager/internal/backend/crypto"
	"passwordManager/internal/backend/dbInterface"
)

func main() {
	fmt.Println("Starting test...")

	password := []byte(crypto.GenerateRandomString(16))
	salt := []byte(crypto.GenerateRandomString(16))

	key, err := crypto.Genkey(password, salt)
	if err != nil {
		fmt.Println("error generating key in main")
	}

	keyHash, err := crypto.HashPassword(key)
	if err != nil {
		fmt.Println("error hashing key in main")
	}

	// Open DB
	err = dbInterface.OpenDb()
	if err != nil {
		fmt.Println("DB open error:", err)
		return
	}

	// Test user values
	username := "testuser"

	// Insert user
	createdUsername, err := dbInterface.InsertUser(username, salt, keyHash)
	if err != nil {
		fmt.Println("InsertUser error:", err)
		return
	}
	fmt.Println("Inserted user:", createdUsername)

	// Fetch user
	user, err := dbInterface.FetchUser(username)
	if err != nil {
		fmt.Println("FetchUser error:", err)
		return
	}
	fmt.Printf("Fetched user: %+v\n", user)

	// Insert password
	accountName := "github"

	accPassword := []byte(crypto.GenerateRandomString(16))

	encryptedPassword, err := crypto.EncryptPassword(accPassword, key)
	if err != nil {
		fmt.Println("error in encryption")
		return
	}

	_, err = dbInterface.InsertPassword(user.Uid, accountName, encryptedPassword)
	if err != nil {
		fmt.Println("InsertPassword error:", err)
		return
	}
	fmt.Println("Inserted password for account:", accountName)

	// Fetch password
	fetchedPwd, err := dbInterface.FetchPassword(user.Uid, accountName)
	if err != nil {
		fmt.Println("FetchPassword error:", err)
		return
	}
	fmt.Println("Fetched password (encrypted):", string(fetchedPwd))

	decryptedPassword, err := crypto.DecryptPassword(fetchedPwd, key)
	if err != nil {
		fmt.Println("decryption error:", err)
		return
	}

	fmt.Println("hopefully the decrypted password:", string(decryptedPassword))

	// Delete user
	_, err = dbInterface.DeleteUser(username, user.Uid)
	if err != nil {
		fmt.Println("DeleteUser error:", err)
		return
	}
	fmt.Println("Deleted user:", username)
}
