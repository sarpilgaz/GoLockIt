package main

import (
	"fmt"
	"passwordManager/internal/backend"
	"passwordManager/internal/backend/dbInterface"
)

func main() {
	fmt.Println("Starting test...")

	var username = "sarp"

	//var myPassword = "idk man this seems strong to me"

	//var myGitHubPassword = "its not like people want to go prying in my weak Github"

	err := dbInterface.OpenDb()
	if err != nil {
		fmt.Println("db conn failed")
	}

	usr, masterPassword, err := backend.AddUser(username, "")
	if err != nil {
		fmt.Println("acc creation failed")
	}

	fmt.Println("account created:", usr, string(masterPassword))

	if backend.CheckUsername(username) {
		fmt.Println("bingo!")
	}

	userInfo, masterKey, err := backend.LogUserIn(username, masterPassword)
	if err != nil {
		fmt.Println("auth failed")
	}

	fmt.Println("auth done: ", userInfo.Name, string(masterKey))

	acc, accPassword, err := backend.AddUserAccount(userInfo, "Github", "sarpilgaz", "lalilulelo", masterKey)
	if err != nil {
		fmt.Println("password adding failed")
	}

	fmt.Println("account password added: ", acc, string(accPassword))

	accPassRound2, accUserRound2, err := backend.GetUserAccount(userInfo, "Github", masterKey)
	if err != nil {
		fmt.Println("password retrival failed")
	}

	fmt.Println("password retrieved: ", acc, accUserRound2, accPassRound2)

	accFinalTime, err := backend.RemoveUser(userInfo, masterPassword)
	if err != nil {
		fmt.Println("acc deletion failed")
	}

	fmt.Println("account deleted:", accFinalTime)
}
