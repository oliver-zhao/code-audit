package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func notesByOwner(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	db.Query(`SELECT * FROM notes WHERE owner = $1`, r.FormValue("owner"))
	db.Exec(`DELETE FROM notes WHERE id = $1`, r.URL.Query().Get("id"))
}

func notesByTag(pool *pgxpool.Pool, r *http.Request) {
	pool.Query(r.Context(), "SELECT * FROM notes WHERE tag = $1", r.FormValue("tag"))
}

func notesByTitle(c *gin.Context, db *sql.DB) {
	db.QueryContext(c.Request.Context(), "SELECT * FROM notes WHERE title = $1", c.Query("t"))
}
