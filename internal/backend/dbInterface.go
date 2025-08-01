package backend

import (
	"database/sql"
	"fmt"
	"passwordManager/internal/userType"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func openDb() {
	var err error
	db, err = sql.Open("sqlite3", "passwordManagerDb.db")
	if err != nil {
		fmt.Println("no")
	}
}

func insertUser(username string, salt string, masterKeyHash string) (string, error) {
	//returns the username of the user created, or possible error
	return "", nil
}

func deleteUser(username string, uid uint8) (string, error) {
	//returns the username of the deleted user, or possible error
	return "", nil
}

func fetchUser(username string) (userType.User, error) {
	//returns the user on a successful login, error otherwise
	var bogus userType.User
	return bogus, nil
}

func fetchPassword(uid uint8, accountName string) (string, error) {
	//returns the hashed password corresponding to the account, or possible error
	return "", nil
}

func insertPassword(uid uint8, accountName string, hashedPassword string) (string, error) {
	//returns the name of the account for which a password was added, or a possible error
	return "", nil
}

/* TODO:
-> remove account
-> change master key
-> change password
-> generate password
*/
