package backend

import (
	"passwordManager/internal/backend/crypto"
	"passwordManager/internal/backend/dbInterface"
	"passwordManager/internal/userType"
)

const SALT_SIZE int = 16
const GEN_PASSWORD_LENGTH int = 16

//Unauthenticated Actions

func AddUser(username string, masterPasswd string) (string, string, error) {
	//empty master key means generate a master password
	//returns the username of the user created, the master password used, or possible error
	var passwdToUse string
	if len(masterPasswd) == 0 {
		passwdToUse = crypto.GenerateRandomString(GEN_PASSWORD_LENGTH)
	} else {
		passwdToUse = masterPasswd
	}

	salt := crypto.GenerateRandomString(SALT_SIZE)
	key, err := crypto.Genkey([]byte(passwdToUse), []byte(salt))
	if err != nil {
		return "", "", err
	}

	hashedKey, err := crypto.HashPassword(key)
	if err != nil {
		return "", "", err
	}

	usr, err := dbInterface.InsertUser(username, []byte(salt), hashedKey)
	if err != nil || usr != username {
		return "", "", err
	}

	return username, passwdToUse, nil
}

func GetUser(username string, masterKey string) (userType.User, error) {
	//returns the user on a successful login, error otherwise
	var bogus userType.User
	return bogus, nil
}

//Authenticated Actions

func GetPassword(user userType.User, accountName string) (string, error) {
	//returns the password corresponding to the account, or possible error
	return "", nil
}

func AddPassword(user userType.User, accountName string, password string) (string, error) {
	//empty password means generate a master key
	//returns the name of the account for which a password was added, or a possible error
	return "", nil
}

func RemoveUser(user userType.User, masterKey string) (string, error) {
	//returns the username of the deleted user, or possible error
	return "", nil
}

/* TODO:
-> remove account: authenticated
-> change master key: authenticated
-> change password: authenticated
*/
