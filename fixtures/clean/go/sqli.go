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
	rows, _ := db.QueryContext(r.Context(), "SELECT * FROM users WHERE role = $1", r.FormValue("role"))
	_ = rows
	db.Exec("DELETE FROM users WHERE id = $1", mux.Vars(r)["id"])
	col := "name"
	switch r.URL.Query().Get("sort") {
	case "created":
		col = "created_at"
	}
	row := db.QueryRow("SELECT name FROM users ORDER BY " + col)
	_ = row
	stmt, _ := db.Prepare("SELECT name FROM users WHERE id = $1")
	stmt.Exec(r.FormValue("id"))
}

func searchUsers(c *gin.Context, dbx *sqlx.DB, gdb *gorm.DB) {
	var users []User
	_ = dbx.Select(&users, "SELECT * FROM users WHERE name LIKE $1", "%"+c.Query("q")+"%")
	gdb.Where("name = ?", c.Param("name")).Find(&users)
	gdb.Raw("SELECT * FROM users WHERE email = ?", c.PostForm("email")).Scan(&users)
	_ = c.Query("page")
}

func counters(db *sql.DB, id int64) {
	db.Exec("UPDATE repository SET num_stars = num_stars + 1 WHERE id = ?", id)
	db.Query("SELECT 1")
}

func profile(db *sql.DB, uid string) {
	db.Query("SELECT full_name FROM profile WHERE user_id = $1", uid)
	db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", "tmp_profile"))
}
