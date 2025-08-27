/* TODO:
-> change master password: authenticated
-> change password of a account: authenticated
-> remove a account and its credentials
-> master password rotation
*/

package backend

import (
	"bytes"
	"fmt"
	"log/slog"
	"passwordManager/internal/backend/crypto"
	"passwordManager/internal/backend/dbInterface"
	"passwordManager/internal/userType"
)

var logger *slog.Logger

func SetLogger(mainLogger *slog.Logger) {
	logger = mainLogger
}

const SALT_SIZE int = 16
const GEN_PASSWORD_LENGTH int = 16

func authenticateUser(username string, masterPassword string) (userType.User, []byte, error) {
	//returns true, the users info, and their generated master key if the given username and password pair is correct, false otherwise
	// intended to be used as a util function inside the API, for example for first log in, or account deletion, etc.
	logger.Info("Attempting to authenticate user", "username", username)
	userInfo, err := dbInterface.FetchUser(username)
	if err != nil {
		switch err {
		case dbInterface.Err0LengthUsername:
			logger.Error("authentication failed:", "error", err)
			return userType.User{}, []byte{}, err
		default:
			logger.Error("authentication failed: given user couldnt be found", "error", err)
			return userType.User{}, []byte{}, fmt.Errorf("given user couldnt be found")
		}
	}

	logger.Debug("User information fetched successfully", "username", username)
	generatedKey, err := crypto.Genkey([]byte(masterPassword), userInfo.Salt)
	if err != nil {
		switch err {
		case crypto.Err0LengthPassword:
			logger.Error("authentication failed:", "error", err)
			return userType.User{}, []byte{}, err
		case crypto.ErrInvalidSalt:
			logger.Error("authentication failed:", "error", err)
			return userType.User{}, []byte{}, fmt.Errorf("internal error, try again later")
		}
	}

	logger.Debug("Generated key successfully", "username", username)
	hashedKey, err := crypto.HashPassword(generatedKey)
	if err != nil {
		logger.Error("authentication failed:", "error", err)
		return userType.User{}, []byte{}, err
	}

	logger.Debug("Hashed key successfully", "username", username)
	if !bytes.Equal(hashedKey, userInfo.MasterKeyHash) {
		logger.Error("authentication failed: mismatch credentials")
		return userType.User{}, []byte{}, fmt.Errorf("authentication failed: invalid credentials")
	}

	logger.Info("User authenticated successfully", "username", username)
	return userInfo, generatedKey, nil
}

//Unauthenticated Actions

func AddUser(username string, masterPasswd string) (string, string, error) {
	logger.Info("Attempting to add a new user", "username", username)

	var passwdToUse string
	if len(masterPasswd) == 0 {
		logger.Debug("No master password provided, generating a random password")
		passwdToUse = crypto.GenerateRandomString(GEN_PASSWORD_LENGTH)
	} else {
		passwdToUse = masterPasswd
	}

	logger.Debug("Generated password to use", "username", username)
	salt := crypto.GenerateRandomString(SALT_SIZE)
	key, err := crypto.Genkey([]byte(passwdToUse), []byte(salt))
	if err != nil {
		switch err {
		case crypto.Err0LengthPassword:
			logger.Error("authentication failed:", "error", err)
			return "", "", err
		case crypto.ErrInvalidSalt:
			logger.Error("authentication failed:", "error", err)
			return "", "", fmt.Errorf("internal error, try again later")
		}
	}

	logger.Debug("Generated key successfully", "username", username)
	hashedKey, err := crypto.HashPassword(key)
	if err != nil {
		logger.Error("authentication failed:", "error", err)
		return "", "", err
	}

	logger.Debug("Hashed key successfully", "username", username)
	inserted_usr, err := dbInterface.InsertUser(username, []byte(salt), hashedKey)
	if err != nil {
		switch err {
		case dbInterface.Err0LengthUsername:
			logger.Error("Add user failed: ", "error", err)
			return "", "", err
		default:
			logger.Error("db error:", "error", err)
			return "", "", fmt.Errorf("internal error, try again later")
		}
	}

	logger.Info("User successfully added", "username", inserted_usr)
	return inserted_usr, passwdToUse, nil
}

func LogUserIn(username string, masterPassword string) (userType.User, []byte, error) {
	//returns the user and the users master Key (derived from the master Password) on a successful login, error otherwise
	user, key, err := authenticateUser(username, masterPassword)
	if err != nil {
		return userType.User{}, []byte{}, err
	}

	return user, key, nil
}

//Authenticated Actions

func GetUserAccount(user userType.User, accountName string, userKey []byte) (string, string, error) {
	//returns the password corresponding to the account, or possible error
	accUsername, encryptedPasswd, err := dbInterface.FetchUserAccount(user.Uid, accountName)
	if err != nil {
		switch err {
		case dbInterface.Err0LengthUserAccname:
			logger.Error("Get user acc failed:", "error", err)
			return "", "", err
		default:
			logger.Error("user account name not found:", "error", err)
			return "", "", fmt.Errorf("given account name couldnt be found")
		}
	}

	decryptedPasswd, err := crypto.DecryptPassword(encryptedPasswd, userKey)
	if err != nil {
		logger.Error("user account password decryption failed:", "error", err)
		return "", "", fmt.Errorf("internal error when retrieving password")
	}

	return accUsername, string(decryptedPasswd), nil
}

func GetUserAccountNames(user userType.User) ([]string, error) {
	accs, err := dbInterface.FetchUserAccounts(user.Uid)
	if err != nil {
		logger.Error("error in retrieving user account names:", "error", err)
		return nil, fmt.Errorf("internal error in retrieving user accounts")
	}
	return accs, nil
}

func AddUserAccount(user userType.User, accountName string, accountUsername string, password string, masterKey []byte) (string, string, error) {
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
		logger.Error("error in encrypting password:", "error", err)
		return "", "", err
	}

	acc, err := dbInterface.InsertUserAccount(user.Uid, accountName, accountUsername, encryptedPasswd)
	if err != nil {
		switch err {
		case dbInterface.Err0LengthUserAccname:
			logger.Error("Add user acc failed:", "error", err)
			return "", "", err
		case dbInterface.Err0LengthUserAccUsername:
			logger.Error("Add user acc failed:", "error", err)
			return "", "", err
		default:
			logger.Error("db error:", "error", err)
			return "", "", fmt.Errorf("internal error, try again later")
		}
	}

	return acc, string(passwdToUse), nil
}

func RemoveUser(user userType.User, masterPassword string) (string, error) {
	_, _, err := authenticateUser(user.Name, masterPassword)
	if err != nil {
		return "", err
	}

	acc, err := dbInterface.DeleteUser(user.Name, user.Uid)
	if err != nil {
		switch err {
		case dbInterface.Err0LengthUsername:
			logger.Error("Remove user failed:", "error", err)
			return "", err
		default:
			logger.Error("db error:", "error", err)
			return "", fmt.Errorf("internal error, try again later")
		}
	}

	return acc, nil
}
