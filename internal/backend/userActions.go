/* TODO:
-> change master password: authenticated
-> change password of a account: authenticated
-> remove a account and its credentials
-> master password rotation
*/

package backend

import (
	"bytes"
	"errors"
	"passwordManager/internal/backend/crypto"
	"passwordManager/internal/backend/dbInterface"
	"passwordManager/internal/userType"
)

const SALT_SIZE int = 16
const GEN_PASSWORD_LENGTH int = 16

// util
func CheckUsername(username string) bool {
	return dbInterface.CheckUsername(username)
}

func authenticateUser(username string, masterPassword string) (bool, userType.User, []byte) {
	//returns true, the users info, and their generated master key if the given username and password pair is correct, false otherwise
	// intended to be used as a util function inside the API, for example for first log in, or account deletion, etc.
	userInfo, err := dbInterface.FetchUser(username)
	if err != nil {
		return false, userType.User{}, []byte{}
	}

	generatedKey, err := crypto.Genkey([]byte(masterPassword), userInfo.Salt)
	if err != nil {
		return false, userType.User{}, []byte{}
	}

	hashedKey, err := crypto.HashPassword(generatedKey)
	if err != nil {
		return false, userType.User{}, []byte{}
	}

	if !bytes.Equal(hashedKey, userInfo.MasterKeyHash) {
		return false, userType.User{}, []byte{}
	}

	return true, userInfo, generatedKey
}

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

func LogUserIn(username string, masterPassword string) (userType.User, []byte, error) {
	//returns the user and the users master Key (derived from the master Password) on a successful login, error otherwise
	auth, user, key := authenticateUser(username, masterPassword)
	if !auth {
		return userType.User{}, []byte{}, errors.New("authentication failed on login attempt")
	}

	return user, key, nil
}

//Authenticated Actions

func GetPassword(user userType.User, accountName string, userKey []byte) (string, error) {
	//returns the password corresponding to the account, or possible error
	encryptedPasswd, err := dbInterface.FetchPassword(user.Uid, accountName)
	if err != nil {
		return "", err
	}

	decryptedPasswd, err := crypto.DecryptPassword(encryptedPasswd, userKey)
	if err != nil {
		return "", err
	}

	return string(decryptedPasswd), nil
}

func AddPassword(user userType.User, accountName string, password string, masterKey []byte) (string, string, error) {
	//empty password means generate a password
	//returns the name of the account for which a password was added, the password added to the account, or a possible error
	var passwdToUse []byte
	if len(password) == 0 {
		passwdToUse = []byte(crypto.GenerateRandomString(GEN_PASSWORD_LENGTH))
	} else {
		passwdToUse = []byte(password)
	}

	encryptedPasswd, err := crypto.EncryptPassword(passwdToUse, masterKey)
	if err != nil {
		return "", "", nil
	}

	acc, err := dbInterface.InsertPassword(user.Uid, accountName, encryptedPasswd)
	if err != nil {
		return "", "", err
	}

	return acc, string(passwdToUse), nil
}

func RemoveUser(user userType.User, masterPassword string) (string, error) {
	auth, _, _ := authenticateUser(user.Name, masterPassword)
	if !auth {
		return "", errors.New("error on account deletion: authentication failed")
	}

	acc, err := dbInterface.DeleteUser(user.Name, user.Uid)
	if err != nil {
		return "", err
	}

	return acc, nil
}
