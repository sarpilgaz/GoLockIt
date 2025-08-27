package main

import (
	"log/slog"
	"os"
	"passwordManager/internal/backend"
	"passwordManager/internal/backend/dbInterface"
	"passwordManager/internal/cli"
)

func main() {
	file, err := os.OpenFile("passwordmanagerlogs.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	logger := slog.New(slog.NewTextHandler(file, nil))
	backend.SetLogger(logger)

	dbInterface.OpenDb()
	if err := dbInterface.OpenDb(); err != nil {
		panic(err)
	}
	cli.RunCLI()
}
