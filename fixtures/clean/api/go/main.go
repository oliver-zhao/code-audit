package main

import (
	"database/sql"
	"os"
	"os/exec"
)

func handler(db *sql.DB) {
	db.Query("SELECT 1")
	exec.Command("sh", "-c", "ls -l")
	os.Open("/data/static.txt")
}
