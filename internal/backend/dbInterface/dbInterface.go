/* TODO:
-> remove account
-> change master key
-> change password
-> generate password
*/

package dbInterface

import (
	"database/sql"
	"errors"
	"fmt"
	"passwordManager/internal/userType"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func OpenDb() error {
	//functiont o open the database
	//returns a error in 2 cases: If the database fails to connect, or if the foreign key pragma cannot be established

	var err error
	db, err = sql.Open("sqlite3", "passwordManagerDb.db")
	if err != nil {
		return fmt.Errorf("failed to open db connection: %w", err)
	}

	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	return nil
}

func InsertUser(username string, salt []byte, masterKeyHash []byte) (string, error) {
	//returns the username of the user created, or 2 possible errors
	//If the given username of the user is empty, or if the query prep fails

	if len(username) == 0 {
		return "", errors.New("db: username given to add user has length 0")
	}

	statement, err := db.Prepare("INSERT INTO users (username, salt, key_hash) VALUES (?, ?, ?)")

	if err != nil {
		fmt.Println("error preparing in insertUser")
		return username, err
	}

	defer statement.Close()

	_, err = statement.Exec(username, salt, masterKeyHash)
	if err != nil {
		fmt.Println("error executing query in insertUser")
		return username, err
	}

	return username, nil
}

func DeleteUser(username string, uid int64) (string, error) {
	//returns the username of the deleted user, or 3 possible errors
	//If the given username is empty, or if query prep fails, or if query execution fails

	if len(username) == 0 {
		return "", errors.New("db: username given to delete user has length 0")
	}

	statement, err := db.Prepare("DELETE FROM users WHERE id = ? AND username = ?")
	if err != nil {
		fmt.Println("error preparing in deleteUser")
		return username, err
	}

	defer statement.Close()

	_, err = statement.Exec(uid, username)
	if err != nil {
		fmt.Println("error executing query in deleteUser")
		return username, err
	}

	return username, nil
}

func FetchUser(username string) (userType.User, error) {
	//returns the user information, or 2 possible errors
	//If the given username is empty, or if no rows with the given params were found

	if len(username) == 0 {
		return userType.User{}, errors.New("db: username given to fetch user has length 0")
	}

	row := db.QueryRow("SELECT id, username, salt, key_hash FROM users WHERE username = ?", username)

	var fetchedUser userType.User = userType.User{}
	err := row.Scan(&fetchedUser.Uid, &fetchedUser.Name, &fetchedUser.Salt, &fetchedUser.MasterKeyHash)
	if err != nil {
		fmt.Println("error executing query in fetchUser")
		return userType.User{}, err
	}

	return fetchedUser, nil
}

func FetchUserAccount(uid int64, accountName string) (string, []byte, error) {
	// returns the account username and encrypted password corresponding to the account, 2 possible errors
	// If the given account name is empty, or if no rows with the given params were found

	if len(accountName) == 0 {
		return "", []byte{}, errors.New("db: account name given to fetch password has length 0")
	}

	row := db.QueryRow("SELECT acc_username, encrypted_data FROM entries WHERE user_id = ? AND name = ?", uid, accountName)

	var accUsername string
	var encryptedData []byte
	err := row.Scan(&accUsername, &encryptedData)
	if err != nil {
		fmt.Println("error executing query in FetchUserAccount")
		return "", []byte{}, err
	}
	return accUsername, encryptedData, nil
}

func FetchUserAccounts(uid int64) ([]string, error) {
	//function to fetch the names the accounts of a user stored. Not usernames of accounts, the names of the accounts
	rows, err := db.Query("SELECT name FROM entries WHERE user_id = ?", uid)
	accNames := make([]string, 0)
	if err != nil {
		return nil, fmt.Errorf("error executing query in FetchUserAccounts: %w", err)
	}

	defer rows.Close()

	for rows.Next() {
		var accName string
		if err := rows.Scan(&accName); err != nil {
			return nil, fmt.Errorf("error scanning row in FetchUserAccounts: %w", err)
		}
		accNames = append(accNames, accName)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows in FetchUserAccounts: %w", err)
	}

	return accNames, nil
}

func InsertUserAccount(uid int64, accountName string, accUsername string, encryptedData []byte) (string, error) {
	// returns the name of the account for which a password was added, or 3 possible errors
	// If the given account name or acc_username is empty, or if query prep fails, or if query execution fails

	if len(accountName) == 0 {
		return "", errors.New("db: account name given to insert account has length 0")
	}
	if len(accUsername) == 0 {
		return "", errors.New("db: acc_username given to insert account has length 0")
	}

	statement, err := db.Prepare("INSERT INTO entries (user_id, name, acc_username, encrypted_data) VALUES (?, ?, ?, ?)")
	if err != nil {
		fmt.Println("error preparing in InsertUserAccount")
		return accountName, err
	}

	defer statement.Close()

	_, err = statement.Exec(uid, accountName, accUsername, encryptedData)
	if err != nil {
		fmt.Println("error executing query in InsertUserAccount")
		return accountName, err
	}

	return accountName, nil
}
