package backend

import "passwordManager/internal/userType"

//Unauthenticated Actions

func addUser(username string, masterKey string) (string, error) {
	//empty master key means generate a master key
	//returns the username of the user created, or possible error
	return "", nil
}

func getUser(username string, masterKey string) (userType.User, error) {
	//returns the user on a successful login, error otherwise
	var bogus userType.User
	return bogus, nil
}

//Authenticated Actions

func getPassword(user userType.User, accountName string) (string, error) {
	//returns the password corresponding to the account, or possible error
	return "", nil
}

func addPassword(user userType.User, accountName string, password string) (string, error) {
	//empty password means generate a master key
	//returns the name of the account for which a password was added, or a possible error
	return "", nil
}

func removeUser(user userType.User, masterKey string) (string, error) {
	//returns the username of the deleted user, or possible error
	return "", nil
}

/* TODO:
-> remove account: authenticated
-> change master key: authenticated
-> change password: authenticated
*/
