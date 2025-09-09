package cli

import (
	"bufio"
	"fmt"
	"os"
	"passwordManager/internal/backend"
	"passwordManager/internal/userType"
	"strings"
)

type authState struct {
	isAuthenticated bool
	user            userType.User
	masterKey       []byte
}

var currAuthState authState = authState{
	isAuthenticated: false,
	user:            userType.User{},
	masterKey:       []byte{},
}

func checkCommandAndAuthStateMatch(cmd string, currAuthState *authState) uint8 {
	// returns 1 if command cannot be used in unauthenticated state
	// 2 if command cannot be used in authenticated state
	// 0 if command can currently be used
	switch cmd {
	case "login":
		if currAuthState.isAuthenticated {
			return 2
		}
	case "logout":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "adduser":
		if currAuthState.isAuthenticated {
			return 2
		}
	case "getaccount":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "getaccounts":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "addaccount":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "removeuser":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "exit", "quit", "help":
		return 0
	default:
		return 0 // command can be used, should fail in processCommand if command is not recognized
	}
	return 0
}

func login(username string, password string, currAuthState *authState) error {

	// input validation
	if len(username) == 0 || len(password) == 0 {
		return fmt.Errorf("username and password cannot be empty")
	}

	account, masterKey, err := backend.LogUserIn(username, password)
	if err != nil {
		return err
	}

	currAuthState.isAuthenticated = true
	currAuthState.user = account
	currAuthState.masterKey = masterKey
	fmt.Println("Login successful.")
	return nil
}

func logout(currAuthState *authState) error {
	if !currAuthState.isAuthenticated {
		return fmt.Errorf("you are not logged in")
	}

	currAuthState.isAuthenticated = false
	currAuthState.user = userType.User{}
	currAuthState.masterKey = []byte{}
	fmt.Println("Logged out successfully.")
	return nil
}

func addUser(username string, masterPassword string) error {

	if len(username) == 0 || len(masterPassword) == 0 {
		return fmt.Errorf("username and password cannot be empty")
	}
	_, _, err := backend.AddUser(username, masterPassword)
	if err != nil {
		return err
	}
	fmt.Println("User added successfully.")
	return nil
}

func getUserAccount(accountName string) error {

	if len(accountName) == 0 {
		return fmt.Errorf("account name cannot be empty")
	}

	accountName = strings.ToLower(accountName)

	accountUsername, accountPassword, err := backend.GetUserAccount(currAuthState.user, accountName, currAuthState.masterKey)
	if err != nil {
		return err
	}

	fmt.Printf("Account: %s\nUsername: %s\nPassword: %s\n", accountName, accountUsername, accountPassword)
	return nil
}

func getUserAccountNames(user userType.User) error {
	accs, err := backend.GetUserAccountNames(user)
	if err != nil {
		return err
	}

	//pretty print the account names retrieved
	if len(accs) == 0 {
		fmt.Println("No accounts found for the user.")
		return nil
	}
	fmt.Println("User accounts:")
	for _, acc := range accs {
		fmt.Println("-", acc)
	}
	fmt.Println("Use getaccount <account_name> to retrieve credentials")
	return nil
}

func addUserAccount(accountName string, accountUsername string, accountPassword string) error {
	if len(accountName) == 0 {
		return fmt.Errorf("account name cannot be empty")
	}

	// Convert account name to lowercase for consistency
	accountName = strings.ToLower(accountName)

	_, _, err := backend.AddUserAccount(currAuthState.user, accountName, accountUsername, accountPassword, currAuthState.masterKey)
	if err != nil {
		return err
	}
	fmt.Println("User account added successfully.")
	return nil
}

func removeUser(masterPassword string) error {
	if len(masterPassword) == 0 {
		return fmt.Errorf("master password cannot be empty")
	}

	account, err := backend.RemoveUser(currAuthState.user, masterPassword)
	if err != nil {
		return err
	}
	fmt.Printf("User account removed successfully. Deleted account: %s\n", account)
	return nil
}

func processCommand(cmd string, args []string, currAuthState *authState) bool {
	// true for continue CLI, false for exit
	switch cmd {
	case "login":
		if len(args) < 3 {
			fmt.Println("Usage: login <username> <password>")
			return true
		}
		err := login(args[1], args[2], currAuthState)
		if err != nil {
			fmt.Println("Login failed:", err)
		}

	case "logout":
		err := logout(currAuthState)
		if err != nil {
			fmt.Println("logout failed: ", err)
		}

	case "adduser":
		if len(args) < 3 {
			fmt.Println("Usage: adduser <username> <master_password>")
			return true
		}
		err := addUser(args[1], args[2])
		if err != nil {
			fmt.Println("adduser failed:", err)
		}

	case "getaccount":
		if len(args) < 2 {
			fmt.Println("Usage: getaccount <account_name>")
			return true
		}
		err := getUserAccount(args[1])
		if err != nil {
			fmt.Println("getaccount failed:", err)
		}

	case "getaccounts":
		if len(args) > 1 {
			fmt.Println("Usage: getaccounts")
			return true
		}
		err := getUserAccountNames(currAuthState.user)
		if err != nil {
			fmt.Println("getaccounts failed:", err)
		}

	case "addaccount":
		if len(args) < 4 {
			fmt.Println("Usage: addaccount <account_name (identification)> <account_username (credential)> <account password>")
			return true
		}
		err := addUserAccount(args[1], args[2], args[3])
		if err != nil {
			fmt.Println("addaccount:", err)
		}

	case "removeuser":
		if len(args) < 2 {
			fmt.Println("Usage: removeuser <master_password>")
			return true
		}
		err := removeUser(args[1])
		if err != nil {
			fmt.Println("removeuser failed:", err)
		}

	case "exit", "quit":
		fmt.Println("Exiting...")
		return false

	case "help":
		if currAuthState.isAuthenticated {
			fmt.Println("Available commands:\n" +
				"  logout\n" +
				"  getaccount <account_name>\n" +
				"  getaccounts\n" +
				"  addaccount <account_name> <account_username> <account_password>\n" +
				"  removeuser <master_password>\n" +
				"  exit | quit\n" +
				"  help")
		} else {
			fmt.Println("Available commands:\n" +
				"  login <username> <password>\n" +
				"  adduser <username> <master_password>\n" +
				"  exit | quit\n" +
				"  help")
		}
	default:
		if currAuthState.isAuthenticated {
			fmt.Println("Unknown command. Type \"help\" for a list of available commands")
		} else {
			fmt.Println("Unknown command. Type \"help\" for a list of available commands")
		}
	}
	return true
}

func RunCLI() {
	reader := bufio.NewReader(os.Stdin)
	for {
		if currAuthState.isAuthenticated {
			fmt.Print("[AUTH] > ")
		} else {
			fmt.Print("[UNAUTH] > ")
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		args := strings.Fields(input)
		cmd := args[0]
		ret := checkCommandAndAuthStateMatch(cmd, &currAuthState)
		if ret == 1 {
			fmt.Println("Cannot use this command when you haven't authenticated")
			continue
		} else if ret == 2 {
			fmt.Println("Cannot use this command when you are authenticated")
			continue
		}

		if !processCommand(cmd, args, &currAuthState) {
			break
		}
	}
}
