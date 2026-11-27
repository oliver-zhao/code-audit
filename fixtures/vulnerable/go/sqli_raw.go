package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func notesByOwner(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	db.Query(fmt.Sprintf(`SELECT * FROM notes WHERE owner = '%s'`, r.FormValue("owner")))
	db.Exec(`DELETE FROM notes WHERE id = ` + r.URL.Query().Get("id"))
}

func notesByTag(pool *pgxpool.Pool, r *http.Request) {
	pool.Query(r.Context(), "SELECT * FROM notes WHERE tag = '"+r.FormValue("tag")+"'")
}

func notesByTitle(c *gin.Context, db *sql.DB) {
	db.QueryContext(c.Request.Context(), "SELECT * FROM notes WHERE title = '"+c.Query("t")+"'")
}

func notesByAuthor(db *sql.DB, author string) {
	db.Query(`SELECT * FROM notes WHERE author = '` + author + `'`)
}
