package main

import (
	"fmt"
	"passwordManager/internal/backend"
)

func main() {
	fmt.Println("Starting test...")

	// Open DB
	err := backend.OpenDb()
	if err != nil {
		fmt.Println("DB open error:", err)
		return
	}

	// Test user values
	username := "testuser"
	salt := []byte("random_salt")
	masterKeyHash := []byte("hashed_master_key")

	// Insert user
	createdUsername, err := backend.InsertUser(username, salt, masterKeyHash)
	if err != nil {
		fmt.Println("InsertUser error:", err)
		return
	}
	fmt.Println("Inserted user:", createdUsername)

	// Fetch user
	user, err := backend.FetchUser(username)
	if err != nil {
		fmt.Println("FetchUser error:", err)
		return
	}
	fmt.Printf("Fetched user: %+v\n", user)

	// Insert password
	accountName := "github"
	passwordHash := []byte("super_secret_password_hash")
	_, err = backend.InsertPassword(user.Uid, accountName, passwordHash)
	if err != nil {
		fmt.Println("InsertPassword error:", err)
		return
	}
	fmt.Println("Inserted password for account:", accountName)

	// Fetch password
	fetchedPwd, err := backend.FetchPassword(user.Uid, accountName)
	if err != nil {
		fmt.Println("FetchPassword error:", err)
		return
	}
	fmt.Println("Fetched password (encrypted):", string(fetchedPwd))

	// Delete user
	_, err = backend.DeleteUser(username, user.Uid)
	if err != nil {
		fmt.Println("DeleteUser error:", err)
		return
	}
	fmt.Println("Deleted user:", username)
}
