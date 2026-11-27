package main

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

func chiDoc(w http.ResponseWriter, r *http.Request) {
	os.ReadFile(filepath.Join("/srv/docs", filepath.Base(chi.URLParam(r, "doc"))))
}

func readNote(w http.ResponseWriter, r *http.Request, base string) {
	os.Open(filepath.Join(base, filepath.Clean("/"+r.PathValue("name"))))
}

func saveNote(w http.ResponseWriter, r *http.Request) {
	os.WriteFile("/var/notes/today.txt", []byte(r.FormValue("note")), 0600)
}

func purgeCache(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["key"])
	if err != nil {
		return
	}
	exec.Command("cache-purge", strconv.Itoa(id)).Run()
}

func echoLookup(c echo.Context) error {
	ip := net.ParseIP(c.QueryParam("host"))
	if ip == nil {
		return nil
	}
	return exec.Command("nslookup", ip.String()).Run()
}

func fiberNext(c *fiber.Ctx) error {
	return c.Redirect("/dashboard")
}
