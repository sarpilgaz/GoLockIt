package main

import (
	"passwordManager/internal/backend/dbInterface"
	"passwordManager/internal/cli"
)

func main() {
	dbInterface.OpenDb()
	if err := dbInterface.OpenDb(); err != nil {
		panic(err)
	}
	cli.RunCLI()
}
