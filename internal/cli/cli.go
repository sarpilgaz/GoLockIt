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
	case "addaccount":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "removeaccount":
		if !currAuthState.isAuthenticated {
			return 1
		}
	case "exit", "quit":
		return 0
	default:
		return 0 // command can be used, should fail in processCommand if command is not recognized
	}
	return 0
}

func login(username string, password string, currAuthState *authState) error {

	// input validation
	if len(username) == 0 || len(password) == 0 {
		fmt.Println("Username and password cannot be empty.")
		return fmt.Errorf("invalid input")
	}

	account, masterKey, err := backend.LogUserIn(username, password)
	if err != nil {
		fmt.Println("Login failed:", err)
		return fmt.Errorf("login failed")
	}

	currAuthState.isAuthenticated = true
	currAuthState.user = account
	currAuthState.masterKey = masterKey
	fmt.Println("Login successful.")
	return nil
}

func logout(currAuthState *authState) error {
	if !currAuthState.isAuthenticated {
		fmt.Println("You are not logged in.")
		return fmt.Errorf("logout failed")
	}

	currAuthState.isAuthenticated = false
	currAuthState.user = userType.User{}
	currAuthState.masterKey = []byte{}
	fmt.Println("Logged out successfully.")
	return nil
}

func addUser(username string, masterPassword string) error {

	if len(username) == 0 || len(masterPassword) == 0 {
		fmt.Println("Username and password cannot be empty.")
		return fmt.Errorf("invalid input")
	}
	_, _, err := backend.AddUser(username, masterPassword)
	if err != nil {
		fmt.Println("Failed to add user:", err)
		return fmt.Errorf("add user failed")
	}
	fmt.Println("User added successfully.")
	return nil
}

func getUserAccount(accountName string) error {

	if len(accountName) == 0 {
		fmt.Println("Account name cannot be empty.")
		return fmt.Errorf("invalid input")
	}

	accountUsername, accountPassword, err := backend.GetUserAccount(currAuthState.user, accountName, currAuthState.masterKey)
	if err != nil {
		fmt.Println("Failed to retrieve account:", err)
		return err
	}

	fmt.Printf("Account: %s\nUsername: %s\nPassword: %s\n", accountName, accountUsername, accountPassword)
	return nil
}

func addUserAccount(accountName string, accountPassword string) error {
	if len(accountName) == 0 {
		fmt.Println("Account name cannot be empty.")
		return fmt.Errorf("invalid input")
	}

	_, _, err := backend.AddUserAccount(currAuthState.user, accountName, "", accountPassword, currAuthState.masterKey)
	if err != nil {
		fmt.Println("Failed to add user account:", err)
		return fmt.Errorf("add user account failed")
	}
	fmt.Println("User account added successfully.")
	return nil
}

func removeUserAccount(masterPassword string) error {
	if len(masterPassword) == 0 {
		fmt.Println("Master password cannot be empty.")
		return fmt.Errorf("invalid input")
	}

	account, err := backend.RemoveUser(currAuthState.user, masterPassword)
	if err != nil {
		fmt.Println("Failed to remove user account:", err)
		return fmt.Errorf("remove user account failed")
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
			return true
		}

	case "logout":
		logout(currAuthState)
		return true

	case "adduser":
		if len(args) < 3 {
			fmt.Println("Usage: adduser <username> <master_password>")
			return true
		}
		err := addUser(args[1], args[2])
		if err != nil {
			fmt.Println("Add user failed:", err)
			return true
		}

	case "getaccount":
		if len(args) < 2 {
			fmt.Println("Usage: getaccount <account_name>")
			return true
		}
		err := getUserAccount(args[1])
		if err != nil {
			fmt.Println("Get account failed:", err)
			return true
		}

	case "addaccount":
		if len(args) < 3 {
			fmt.Println("Usage: addaccount <account_name> <account password>")
			return true
		}
		err := addUserAccount(args[1], args[2])
		if err != nil {
			fmt.Println("Add account failed:", err)
			return true
		}

	case "removeaccount":
		if len(args) < 2 {
			fmt.Println("Usage: removeaccount <master_password>")
			return true
		}
		err := removeUserAccount(args[1])
		if err != nil {
			fmt.Println("Remove account failed:", err)
			return true
		}

	case "exit", "quit":
		fmt.Println("Exiting...")
		return false
	default:
		if currAuthState.isAuthenticated {
			fmt.Println("Unknown command. Available: logout, exit")
		} else {
			fmt.Println("Unknown command. Available: login, exit")
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
