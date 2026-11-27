package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"gorm.io/gorm"
)

type User struct{ Name string }

func listUsers(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	rows, _ := db.QueryContext(r.Context(), "SELECT * FROM users WHERE role = '"+r.FormValue("role")+"'")
	_ = rows
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %s", mux.Vars(r)["id"]))
	row := db.QueryRow("SELECT name FROM users ORDER BY " + r.URL.Query().Get("sort"))
	_ = row
}

func searchUsers(c *gin.Context, dbx *sqlx.DB, gdb *gorm.DB) {
	var users []User
	_ = dbx.Select(&users, "SELECT * FROM users WHERE name LIKE '%"+c.Query("q")+"%'")
	gdb.Where(fmt.Sprintf("name = '%s'", c.Param("name"))).Find(&users)
	gdb.Order(c.Query("order")).Find(&users)
	gdb.Raw("SELECT * FROM users WHERE email = '" + c.PostForm("email") + "'").Scan(&users)
}

func reportByOwner(db *sql.DB, owner string) {
	db.Query(fmt.Sprintf("SELECT * FROM reports WHERE owner = '%s'", owner))
	db.Exec("UPDATE accounts SET locked = 1 WHERE login = '" + owner + "'")
}

func runReport(db *sql.DB, query string) {
	db.Query(query)
}

func profile(db *sql.DB, uid string) {
	q := fmt.Sprintf("SELECT full_name FROM profile WHERE user_id = %s", uid)
	db.Query(q)
}
