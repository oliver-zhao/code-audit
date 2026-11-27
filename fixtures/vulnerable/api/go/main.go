package main

import (
	"database/sql"
	"os"
	"os/exec"
)

func handler(db *sql.DB, query, script, name string) {
	db.Query(query)
	exec.Command("sh", "-c", script)
	os.Open("/data/" + name)
}
